# PassKee — Architecture

Condensed architectural reference. Canonical plan: `~/.claude/plans/floofy-bubbling-axolotl.md`.

## Two processes

```
[ Browser / native app ]  navigator.credentials.create|get()
           |
           v
[ webauthn.dll ]          Windows 11 24H2 build 26100.6725+
           |
           v
[ PassKee.Provider ]      MSIX sidecar — Rust + windows-rs
   IPluginAuthenticator     COM-activated on demand (no tray process)
   CTAP2 CBOR en/decode     WebAuthNPluginAddAuthenticator on first launch
   Windows Hello UV         via WebAuthNPluginPerformUserVerification
           |
           | Named pipe  \\.\pipe\PassKee.<sessionId>
           | ACL: current user SID. Plugin verifies the sidecar's package
           | family name and a per-launch HKCU handshake nonce.
           | JSON-RPC 2.0, line-delimited.
           v
[ PassKee.Plugin ]        KeePass 2.x plugin (.NET Framework 4.8)
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
| `passkee.hello` | Handshake: client pkg family name + HKCU nonce |
| `passkee.createPasskey` | Generate + store a new passkey |
| `passkee.listCredentials` | Enumerate credentials for an RP |
| `passkee.signAssertion` | Sign authData / clientDataHash |
| `passkee.deleteCredential` | Remove a credential |
| `passkee.enumerateForSync` | Full list for Windows Settings mirror |

Errors are JSON-RPC error envelopes mapped to CTAP2 status codes inside the sidecar.

## Storage schema

One `PwEntry` per credential in a dedicated "Passkeys" group. Title: `<rpName> / <userDisplayName>`.

| Field | Location | Protected |
|---|---|---|
| credentialId | `Strings["PassKee.credentialId"]` (Base64URL) | no |
| rpId / rpName | `Strings["PassKee.rpId"]` / `.rpName` | no |
| userHandle / userName / userDisplayName | `Strings["PassKee.user*"]` | no |
| algId | `CustomData["PassKee.algId"]` (COSE int) | no |
| **privateKeyPkcs8** | `Strings["PassKee.privateKey"]` as **ProtectedString** | **yes** |
| publicKeyCose | `Binaries["PassKee.publicKey.cbor"]` (CBOR) | no |
| signCount | `CustomData["PassKee.signCount"]` — always `0` | no |
| aaguid | `CustomData["PassKee.aaguid"]` — zeros for `none` attestation | no |
| transports / flags | `CustomData["PassKee.*"]` | no |

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
