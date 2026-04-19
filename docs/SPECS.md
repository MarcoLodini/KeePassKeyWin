# KeePassKeyWin — Spec References

## WebAuthn / FIDO2

- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/) — Candidate Recommendation
- [FIDO CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) — Proposed Standard
- [COSE (RFC 9052)](https://www.rfc-editor.org/rfc/rfc9052) — public key encoding
- [CBOR (RFC 8949)](https://www.rfc-editor.org/rfc/rfc8949) — binary encoding used throughout CTAP2

## Windows APIs

- [Plugin passkey manager support](https://learn.microsoft.com/en-us/windows/apps/develop/security/third-party) — primary developer guide
- [WebAuthn APIs on Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis)
- [Microsoft PasskeyManager sample](https://github.com/microsoft/windows-classic-samples/tree/main/Samples/PasskeyManager) — C++/WinUI 3 reference
- [`microsoft/webauthn`](https://github.com/microsoft/webauthn) — `webauthn.h` + `pluginauthenticator.h` headers

## KeePass

- [Plugin Development (2.x)](https://keepass.info/help/v2_dev/plg_index.html)
- [KeePass Security](https://keepass.info/help/base/security.html)
- [KeePass 2.61 Release Notes](https://keepass.info/news/n260304_2.61.html)

## Cryptography notes

- **ECDSA signature encoding on .NET** — `ECDsa.SignData()` returns IEEE P1363 (`r || s`); WebAuthn expects DER ASN.1 (`SEQUENCE { INTEGER r, INTEGER s }`). Conversion helper lives at `src/KeePassKeyWin.Plugin/Crypto/EcdsaSigner.cs` (to be created in Phase 0.5).
- [Imperial Violet — On signCount semantics](https://www.imperialviolet.org/2023/08/05/signature-counters.html)
- [Yubico — PRF / hmac-secret CTAP2 deep dive](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html) — reference for the post-v1 `hmac-secret`/`prf` extension.

## Test RPs

- [webauthn.io](https://webauthn.io/) — Duo Labs demo RP
- [passkeys-debugger.io](https://www.passkeys-debugger.io/) — diagnostics
- [passkeys.dev test-site catalogue](https://passkeys.dev/docs/tools-libraries/test-sites/)

## Reference implementations

- [KeePassRPC](https://github.com/kee-org/keepassrpc) — plugin IPC pattern
- [KeePassOTP](https://github.com/Rookiestyle/KeePassOTP) — protected-string storage
- [1Password/passkey-rs](https://github.com/1Password/passkey-rs) — Rust authenticator types + CBOR
- [Bitwarden clients PR #17316](https://github.com/bitwarden/clients/pull/17316) — Rust + `windows-rs` COM provider
