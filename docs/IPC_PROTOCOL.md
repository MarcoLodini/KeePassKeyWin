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
    "clientPkgFamilyName": "KeePassKeyWin.Provider_4fv17arhjxxvg",
    "handshakeNonce": "<64-char hex nonce>",
    "opSignPublicKeyB64": "<base64-std-encoded BCRYPT_PUBLIC_KEY_BLOB>"
  }
}
```

**Fields**:
- `clientPkgFamilyName` — required. Must equal `KeePassKeyWin.Provider_4fv17arhjxxvg` exactly.
- `handshakeNonce` — required. 64-char hex nonce from `HKEY_CURRENT_USER\Software\KeePassKeyWin\HandshakeNonce`.
- `opSignPublicKeyB64` — optional (Phase 5.UV.1+). The 72-byte `BCRYPT_ECCKEY_BLOB` for the Windows op-signing
  public key (P-256), base64-standard encoded (RFC 4648, with padding). The plugin caches this for plugin-side
  signature verification in Phase 5.UV.2 and 5.UV.4. Absent when the sidecar's key-fetch fails; the plugin
  treats absence as backward-compatible (the cache is left empty). **Phase 5.UV.4 will make this field required.**

**Validation**:
1. `clientPkgFamilyName` must equal `KeePassKeyWin.Provider_4fv17arhjxxvg` exactly.
2. `handshakeNonce` must match the value stored at `HKEY_CURRENT_USER\Software\KeePassKeyWin\HandshakeNonce` (REG_SZ).
3. The nonce is deleted from the registry on first successful use (single-use).
4. `opSignPublicKeyB64`, if present, must be valid base64-std. Malformed base64 is logged and silently ignored
   (the handshake still succeeds).

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

## Raw CTAP2 methods (post-handshake, dispatch path)

The sidecar's COM dispatch layer (`com::server::dispatch_operation`) forwards every
`MakeCredential` / `GetAssertion` from `webauthn.dll` to the plugin via these methods.

### `keepasskeywin.makeCredentialRaw` and `keepasskeywin.getAssertionRaw`

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "keepasskeywin.makeCredentialRaw",
  "params": {
    "cbor": "<base64-std of the CTAP2 input bytes (== pbEncodedRequest)>",
    "uv": true,
    "pbRequestSignatureB64": "<base64-std of the IEEE-P1363 ECDSA-P256 signature>"
  }
}
```

**Fields**:
- `cbor` — required. Base64-std of the raw `pbEncodedRequest` bytes (the CTAP2
  authenticatorMakeCredential / authenticatorGetAssertion input map). The plugin
  hashes these bytes with SHA-256 to recover the message digest covered by
  `pbRequestSignature`.
- `uv` — required. Boolean reflecting the result of the Windows Hello UV prompt
  the sidecar performed before forwarding. Currently trusted as-is by the plugin
  (Phase 5.UV.4 will re-verify the UV signature plugin-side).
- `pbRequestSignatureB64` — required (Phase 5.UV.2+). Base64-std of the raw
  `WEBAUTHN_PLUGIN_OPERATION_REQUEST.pbRequestSignature` bytes. The plugin verifies
  this against `OpSignPubKeyCache.Current` (populated from the hello handshake)
  using ECDSA-P256 + SHA-256 in IEEE-P1363 raw format. **The plugin rejects the
  request if any of the following is true**:
  - The op-sign pubkey cache is empty (typically: hello did not include
    `opSignPublicKeyB64`).
  - `pbRequestSignatureB64` is missing, empty, or not valid base64-std.
  - `EcdsaVerifier.Verify(cache, cborBytes, signatureBytes)` returns false.

  Setting `KEEPASSKEYWIN_SKIP_PLUGIN_SIG_VERIFY=1` (or `true` / `yes`) on the
  plugin process bypasses the gate entirely — for development only.

**Belt-and-braces**: the sidecar still verifies the same signature server-side
(`com::request_sig::verify_request_signature`) through Phase 5.UV.2. The
sidecar-side gate is removed in Phase 5.UV.5 once the plugin-side gate is the
sole source of truth.

**Result shape**: `{ "cbor": "<base64-std of the CTAP2 response>" }` plus
makeCredential-only metadata fields documented in the C# `VaultHandler`.

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
