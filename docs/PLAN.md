# PassKee — Implementation Plan (live)

Live task tracking. Canonical architectural plan lives at `~/.claude/plans/floofy-bubbling-axolotl.md` (outside the repo). In-repo summary: [`ARCHITECTURE.md`](ARCHITECTURE.md).

Migrate discrete implementable tasks to GitHub Issues once the architecture stabilizes and rewrites slow down.

## Phase 0 — Scaffolding ✓

- [x] Repo directory structure
- [x] Project `MEMORY.md`
- [x] `README.md` with OS requirement + v1 non-goals
- [x] `LICENSE` (GPL-3 notice)
- [x] `.gitignore` (C# + Rust + MSIX)
- [x] `docs/PLAN.md`, `docs/ARCHITECTURE.md`, `docs/SPECS.md`
- [x] `src/PassKee.Plugin/` — SDK-style csproj targeting `net48`
- [x] `src/PassKee.Provider/` — Rust cargo project

## Phase 0.5 — De-risk crypto + storage (no MSIX/COM)

Validate the hardest correctness-sensitive parts — crypto, CBOR, storage, IPC — against a real browser via Chrome DevTools virtual authenticator, before touching any Windows Plug-in Authenticator integration.

- [ ] Plugin: ES256 keygen via `ECDsa.Create(ECCurve.NamedCurves.nistP256)`
- [ ] Plugin: PKCS#8 private key import/export round-trip
- [ ] Plugin: IEEE P1363 `r || s` → DER ASN.1 signature conversion helper + tests
- [ ] Plugin: CBOR encoder (authData, COSE_Key) — evaluate `PeterO.Cbor` vs `Dahomey.Cbor` for net48 compatibility
- [ ] Plugin: PwEntry ↔ passkey record mapping; "Passkeys" group management
  - `KeePassDir` env var / MSBuild property selects real `KeePass.exe` vs stub; set `KeePassDir="C:\Program Files\KeePass Password Safe 2"` for production builds, unset for Linux/CI.
- [ ] Plugin: JSON-RPC 2.0 server over named pipe; method dispatch
- [ ] Plugin: OS version gate — refuse activation outside Win11 24H2 26100.6725+
- [ ] Harness: standalone C# app that drives Chrome DevTools virtual authenticator via the DevTools Protocol, routing CTAP2 calls to the plugin's JSON-RPC pipe
- [ ] E2E: register + authenticate on [webauthn.io](https://webauthn.io) via the harness through the plugin

## Phase 1 — Plugin skeleton (production-grade)

- [x] OS version gate via `RtlGetVersion` P/Invoke (`OsVersionCheck`); graceful degradation (log + return true, skip pipe)
- [ ] Single-instance pipe (`\\.\pipe\PassKee.<sessionId>`); second-instance detection + warning
- [ ] Handshake: client package family + HKCU nonce verification
- [ ] Full JSON-RPC method surface (hello, createPasskey, listCredentials, signAssertion, deleteCredential, enumerateForSync)
- [x] KeePass Tools menu entry (About, Show Passkeys folder, OS compatibility) + entry editor read-only passkey tab (`MenuEntry`, `PasskeyEntryDecorator`, `AboutDialog`)
- [ ] Unit test suite lifted from Phase 0.5
- [x] `OsVersionCheckTests` (9 tests, pure-logic, runs on Linux net8.0)

## Phase 2 — Provider skeleton (self-signed MSIX, dev machine only)

- [ ] Generate `IPluginAuthenticator` bindings from Windows SDK via `windows-bindgen`
- [ ] COM server stub — vtable registration, class factory
- [ ] `Package.appxmanifest` with `windows.comServer` extension
- [ ] `WebAuthNPluginAddAuthenticator` call on first activation
- [ ] Named-pipe client with retry/backoff + handshake
- [ ] Verify appearance in Settings → Accounts → Passkeys → Advanced options

## Phase 3 — End-to-end `MakeCredential`

- [ ] CBOR decode of `MakeCredential` request
- [ ] authData construction (flags byte, rpIdHash, signCount BE uint32, AAGUID, COSE_Key canonical CBOR)
- [ ] Windows Hello UV via `WebAuthNPluginPerformUserVerification`
- [ ] `passkee.createPasskey` IPC round-trip
- [ ] webauthn.io from Edge: register succeeds, server-side attestation verification passes

## Phase 4 — End-to-end `GetAssertion`

- [ ] Discoverable credential enumeration via `passkee.listCredentials`
- [ ] Credential selection UI (only when multiple match)
- [ ] `WebAuthNPluginAuthenticatorAddCredentials` sync after creation
- [ ] `passkee.signAssertion` IPC round-trip
- [ ] webauthn.io from Edge: login succeeds, signature verifies server-side
- [ ] Settings page reflects credential adds/removes

## Phase 5 — Polish + RS256

- [ ] RS256 (COSE `-257`) algorithm support
- [ ] Plugin UI: list / delete passkeys from inside KeePass
- [ ] Sidecar confirmation UI when KeePass is minimized
- [ ] `credProps` extension

## Phase 6 — Distribution

- [ ] Code-signing decision (self-signed for testers vs OV cert for release)
- [ ] Signed MSIX release artifact
- [ ] KeePass plugin page entry + GitHub release

## Post-v1

- `hmac-secret` / `prf`
- EdDSA
- Self-attestation with real AAGUID
- FIDO MDS metadata registration
- Multi-instance KeePass support
- Auto-launch / unlock prompt from sidecar
