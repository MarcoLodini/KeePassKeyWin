# KeePassKeyWin — Architecture

Condensed architectural reference. See [`PLAN.md`](PLAN.md) for the live implementation log.

## Two processes

```
[ Browser / native app ]  navigator.credentials.create|get()
           |
           v
[ webauthn.dll ]          Windows 11 24H2 build 26100.6725+
           |
           v
[ KeePassKeyWin.Provider ]      MSIX sidecar — Rust + windows-rs
   IPluginAuthenticator     COM-activated on demand (no tray process)
   CTAP2 CBOR en/decode     WebAuthNPluginAddAuthenticator on first launch
   Windows Hello UV         via WebAuthNPluginPerformUserVerification
           |
           | Named pipe  \\.\pipe\KeePassKeyWin.<sessionId>
           | ACL: current user SID. Plugin verifies the sidecar's package
           | family name and a per-launch HKCU handshake nonce.
           | JSON-RPC 2.0, line-delimited.
           v
[ KeePassKeyWin.Plugin ]        KeePass 2.x plugin (.NET Framework 4.8)
   Pipe server              Initialize() / Terminate()
   Single-instance          First plugin wins the pipe name
   Vault store              One PwEntry per credential in "Passkeys" group
   ECDsa keygen + sign      Private key NEVER leaves this process
           |
           v
[ Open .kdbx ]            PKCS#8 private key in ProtectedString
                          Metadata in Strings / CustomData / Binaries
```

## Why two processes

- MSIX packaging is required to register an `IPluginAuthenticator` COM server (class is declared in `Package.appxmanifest`).
- KeePass 2.x is an unpackaged .NET Framework 4.8 WinForms app — it cannot host a packaged COM server.
- Therefore the provider lives in a separate MSIX-packaged process, communicating with the KeePass plugin over IPC.

## Why Rust for the sidecar

- No managed .NET wrapper exists for `IPluginAuthenticator` — must be C++ or Rust.
- Rust via `windows-rs` gives deterministic cargo builds, memory safety, and the 1Password [`passkey-rs`](https://github.com/1Password/passkey-rs) crate for CBOR + passkey types.
- Upfront cost: ~2-3 days to generate COM bindings (the interface isn't yet in the pre-generated `windows` crate).

## Why the KeePass plugin stays on .NET Framework 4.8

KeePass 2.x targets .NET Framework 4.8. Plugins load in-process via `Assembly.LoadFrom` into KeePass's CLR. The .NET Framework CLR and the modern .NET (5+) CLR are different runtimes — a .NET 8 DLL cannot be loaded into a .NET Framework process. Upstream constraint; not negotiable until KeePass itself ports.

All modern-stack work (CBOR, `windows-rs`, crypto libraries, async runtime) lives in the sidecar — a separate process where we're unconstrained.

## Why the private key never leaves the plugin

On `GetAssertion`, the sidecar sends `authData || clientDataHash` to the plugin; the plugin signs in-process and returns the signature bytes. Key material stays inside the process that owns the encrypted KDBX. IPC transports unsigned input in, signed output back.

## IPC protocol (JSON-RPC 2.0)

Methods (sidecar → plugin):

| Method | Purpose |
|---|---|
| `keepasskeywin.hello` | Handshake: client pkg family name + HKCU nonce + op-sign pubkey blob (5.UV.1+) |
| `keepasskeywin.makeCredentialRaw` | Forward raw CTAP2 `authenticatorMakeCredential` (dispatch path) |
| `keepasskeywin.getAssertionRaw` | Forward raw CTAP2 `authenticatorGetAssertion` (dispatch path) |
| `keepasskeywin.createPasskey` | Generate + store a new passkey (legacy; plugin-internal helper) |
| `keepasskeywin.listCredentials` | Enumerate credentials for an RP |
| `keepasskeywin.signAssertion` | Sign authData / clientDataHash (legacy; plugin-internal helper) |
| `keepasskeywin.deleteCredential` | Remove a credential |
| `keepasskeywin.enumerateForSync` | Full list for Windows Settings mirror |

Errors are JSON-RPC error envelopes mapped to CTAP2 status codes inside the sidecar.

### Trust boundary (Phase 5.UV.4 onward)

Two plugin-side verification gates protect every `makeCredentialRaw` / `getAssertionRaw` call:

**Gate 1 — `pbRequestSignature` (Phase 5.UV.2+):** Every dispatch carries
`pbRequestSignatureB64` — Windows' op-signing ECDSA-P256 signature over
`SHA-256(pbEncodedRequest)`. The plugin verifies this against `OpSignPubKeyCache.Current`
(populated from the hello handshake's `opSignPublicKeyB64`). The plugin is the sole
verifier since 5.UV.5 removed the sidecar-side gate; the sidecar forwards the raw bytes
but performs no crypto on them.

> **Accepted trade-off (5.UV.5):** The pre-5.UV.5 sidecar gate ran *before*
> `WebAuthNPluginPerformUserVerification`, so a forged or malformed request
> was rejected before any Windows Hello prompt could fire. Post-5.UV.5, sig
> verification happens plugin-side after the UV call, so a forged request
> can elicit a biometric prompt before the plugin rejects it. The vault
> remains unreachable in either case. Forging the op-sign signature requires
> local code execution as the user (the per-process op-signing key is held
> by `webauthn.dll`); at that level of compromise, an unsolicited Hello
> prompt is not a meaningful escalation. Centralising verification
> plugin-side eliminated the keypair-desync race documented in pre-5.UV.5
> diagnostics and removed a latent NCrypt verify bug.

**Gate 2 — UV response signature (Phase 5.UV.4+):** Every dispatch also carries
`uvSignatureB64` (the UV response signature) and `uvBindingTier` (which Windows UV
entrypoint resolved). For v2-tier dispatches (`"v2_stable"` / `"v2_experimental"`),
the plugin verifies `uvSignatureB64` against `OpSignPubKeyCache.Current` using
`EcdsaVerifier.VerifyAcceptingEitherFormat` (accepts both IEEE P1363 and DER formats
for robustness against Windows API format drift). For v1-tier dispatches, plugin-side
cryptographic verification is not possible (v1 UV signature covers no caller-supplied
buffer); the plugin shows a once-per-process Yes/No confirmation dialog and caches
the user's decision for the plugin-process lifetime.

> **Note (5.UV.7):** On Windows 11 24H2 build 26100.6725+ specifically, all dispatches
> degrade to v1 at call time because Microsoft's stable `WebAuthNPluginPerformUserVerification2`
> export is a forward-declared stub returning E_NOTIMPL. The sidecar detects this on the
> first call, falls through to v1, and caches the decision for the process lifetime.
> Plugin-side behaviour is identical to a load-time-resolved v1 dispatch (tier=v1, fallback
> dialog fires). A future Windows update shipping the actual implementation will be
> adopted automatically on the next COM activation.

`opSignPublicKeyB64` is **required** in the hello handshake since 5.UV.4. Absence or
malformed base64 rejects the hello with `-32602 InvalidParams`; the sidecar returns
`Err` from `handshake()` before sending the hello if the key-fetch fails.

See `IPC_PROTOCOL.md` for the full field schema. A dedicated trust-model section
lands in 5.UV.6.

## Storage schema

One `PwEntry` per credential in a dedicated "Passkeys" group. Title: `<rpName> / <userDisplayName>`.

| Field | Location | Protected |
|---|---|---|
| credentialId | `Strings["KeePassKeyWin.credentialId"]` (Base64URL) | no |
| rpId / rpName | `Strings["KeePassKeyWin.rpId"]` / `.rpName` | no |
| userHandle / userName / userDisplayName | `Strings["KeePassKeyWin.user*"]` | no |
| algId | `CustomData["KeePassKeyWin.algId"]` (COSE int) | no |
| **privateKeyPkcs8** | `Strings["KeePassKeyWin.privateKey"]` as **ProtectedString** | **yes** |
| publicKeyCose | `Binaries["KeePassKeyWin.publicKey.cbor"]` (CBOR) | no |
| signCount | `CustomData["KeePassKeyWin.signCount"]` — always `0` | no |
| aaguid | `CustomData["KeePassKeyWin.aaguid"]` — zeros for `none` attestation | no |
| transports / flags | `CustomData["KeePassKeyWin.*"]` | no |

**PKCS#8** is used over raw EC scalar so the storage is algorithm-agnostic (RS256/EdDSA future-proofing). **signCount=0** matches Apple/Google synced-passkey behavior and is permitted by WebAuthn L3.

## Non-goals for v1

- `hmac-secret` / `prf` extension
- Enterprise attestation / real AAGUID
- Multiple KeePass instances with different vaults

## Pattern references

- [KeePassRPC](https://github.com/kee-org/keepassrpc) — canonical KeePass plugin hosting a long-running IPC listener.
- [KeePassOTP](https://github.com/Rookiestyle/KeePassOTP) — protected-string secret storage inside KeePass entries.
- [microsoft/windows-classic-samples — PasskeyManager](https://github.com/microsoft/windows-classic-samples/tree/main/Samples/PasskeyManager) — C++/WinUI 3 reference; we mirror its COM structure in Rust.
- [1Password/passkey-rs](https://github.com/1Password/passkey-rs) — CBOR + passkey types only; we do not adopt its authenticator state machine.
- [Bitwarden clients PR #17316](https://github.com/bitwarden/clients/pull/17316) — Rust + `windows-rs` COM provider pattern (GPL-3, study only).
