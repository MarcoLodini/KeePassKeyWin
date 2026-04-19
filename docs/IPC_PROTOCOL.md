# KeePassKeyWin IPC Protocol

JSON-RPC 2.0 over a named pipe. Transport and framing details below.
Method handler details for the credential operations are documented in each method's section.

## Transport

- **Pipe name**: `\\.\pipe\KeePassKeyWin.<sessionId>` where `sessionId` = `Process.GetCurrentProcess().SessionId`
- **Mode**: byte-stream, in/out, single connection (single-instance v1)
- **ACL**: restricted to the current user's Windows SID (`PipeSecurity` with `FullControl` for the process owner only)
- **Encoding**: UTF-8, no BOM
- **Framing**: line-delimited — each request and each response is a single JSON line terminated by `\n`

## Request format (client → plugin)

```json
{"jsonrpc":"2.0","id":1,"method":"keepasskeywin.hello","params":{...}}
```

- `id`: integer or string; required for all non-notification requests
- `params`: object (never positional array)
- No notifications are defined (all requests expect a response)

## Response format (plugin → client)

Success:
```json
{"jsonrpc":"2.0","id":1,"result":"ok"}
```

Error:
```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Invalid or already-used nonce."}}
```

## Error codes

| Code | Constant | Meaning |
|---|---|---|
| -32700 | ParseError | Malformed JSON |
| -32600 | InvalidRequest | Missing or invalid envelope fields |
| -32601 | MethodNotFound | Method name not recognised |
| -32602 | InvalidParams | Method params missing or wrong type |
| -32603 | InternalError | Unexpected server-side exception |
| -32000 | HandshakeRequired | Request received before `keepasskeywin.hello` completed |
| -32001 | HandshakeInvalid | Nonce mismatch, already-used nonce, or wrong package family |
| -32010 | VaultLocked | KeePass vault is locked or closed |
| -32020 | CredentialNotFound | credentialId not found in "Passkeys" group |

## Handshake

The **first** request on every connection must be `keepasskeywin.hello`. All other methods return `-32000 HandshakeRequired` until the handshake succeeds.

### `keepasskeywin.hello`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "keepasskeywin.hello",
  "params": {
    "clientPkgFamilyName": "KeePassKeyWin.Provider_rh4edrm0by30m",
    "handshakeNonce": "<64-char hex nonce>"
  }
}
```

**Validation**:
1. `clientPkgFamilyName` must equal `KeePassKeyWin.Provider_rh4edrm0by30m` exactly.
2. `handshakeNonce` must match the value stored at `HKEY_CURRENT_USER\Software\KeePassKeyWin\HandshakeNonce` (REG_SZ).
3. The nonce is deleted from the registry on first successful use (single-use).

**Success response**:
```json
{"jsonrpc":"2.0","id":1,"result":"ok"}
```

**Error responses**: code `-32001` for any validation failure.

## Credential methods

Documented here as stubs; full parameter and result schemas are added by plugin-core in Task #6.

| Method | Direction | Purpose |
|---|---|---|
| `keepasskeywin.createPasskey` | sidecar → plugin | Generate + store a new ES256 passkey |
| `keepasskeywin.listCredentials` | sidecar → plugin | Enumerate credentials for a given rpId |
| `keepasskeywin.signAssertion` | sidecar → plugin | Sign `authData \|\| clientDataHash` with the stored private key |
| `keepasskeywin.deleteCredential` | sidecar → plugin | Remove a passkey by credentialId |
| `keepasskeywin.enumerateForSync` | sidecar → plugin | Return full credential list for Windows Settings sync |

Until plugin-core wires these up, each returns `-32601 MethodNotFound`.

## Nonce lifecycle

```
Plugin Initialize()
  └─ RegistryNonceStore.Initialize()
       └─ Writes random 32-byte hex nonce to HKCU\Software\KeePassKeyWin\HandshakeNonce

Sidecar launch
  └─ Reads nonce from HKCU
  └─ Sends keepasskeywin.hello{clientPkgFamilyName, handshakeNonce}

Plugin receives hello
  └─ Validates pkg family + nonce
  └─ Deletes nonce from registry (single-use)
  └─ Sets ConnectionContext.HandshakeComplete = true

Plugin Terminate()
  └─ RegistryNonceStore.Clear() — deletes any unused nonce from registry
```

## Connection lifecycle

1. Plugin starts pipe server on `\\.\pipe\KeePassKeyWin.<sessionId>`.
2. If another plugin instance already owns the pipe name, the second instance logs a warning and stays passive.
3. Sidecar connects; plugin accepts and spawns a dedicated `ServeConnection` loop.
4. Client sends one request per line; plugin replies with one response line.
5. Connection ends when the client closes the pipe; server loops back to accept the next connection.
