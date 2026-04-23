# KeePassKeyWin — Implementation Plan (live)

Live task tracking — see [`ARCHITECTURE.md`](ARCHITECTURE.md) for the design reference. This file is the maintainer's development log; unchecked items are deferrals, not promises.

Migrate discrete implementable tasks to GitHub Issues once the architecture stabilizes and rewrites slow down.

## Phase 0 — Scaffolding ✓

- [x] Repo directory structure
- [x] `README.md` with OS requirement + v1 non-goals
- [x] `LICENSE` (GPL-3 notice)
- [x] `.gitignore` (C# + Rust + MSIX)
- [x] `docs/PLAN.md`, `docs/ARCHITECTURE.md`, `docs/SPECS.md`
- [x] `src/KeePassKeyWin.Plugin/` — SDK-style csproj targeting `net48`
- [x] `src/KeePassKeyWin.Provider/` — Rust cargo project

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
- [x] Harness: standalone C# app that drives Chrome DevTools virtual authenticator via the DevTools Protocol, routing CTAP2 calls to the plugin's JSON-RPC pipe
- [ ] E2E: register + authenticate on [webauthn.io](https://webauthn.io) via the harness through the plugin
- [x] Windows validation runbook (`docs/WINDOWS_VALIDATION.md`) + deploy/smoke scripts (`scripts/`)

## Phase 1 — Plugin skeleton (production-grade)

- [x] OS version gate via `RtlGetVersion` P/Invoke (`OsVersionCheck`); graceful degradation (log + return true, skip pipe)
- [ ] Single-instance pipe (`\\.\pipe\KeePassKeyWin.<sessionId>`); second-instance detection + warning
- [ ] Handshake: client package family + HKCU nonce verification
- [ ] Full JSON-RPC method surface (hello, createPasskey, listCredentials, signAssertion, deleteCredential, enumerateForSync)
- [x] KeePass Tools menu entry (About, Show Passkeys folder, OS compatibility) + entry editor read-only passkey tab (`MenuEntry`, `PasskeyEntryDecorator`, `AboutDialog`)
- [ ] Unit test suite lifted from Phase 0.5
- [x] `OsVersionCheckTests` (9 tests, pure-logic, runs on Linux net8.0)

## Phase 2 — Provider skeleton (self-signed MSIX, dev machine only)

### Phase 2a — Rust IPC client + CTAP2 types ✓

- [x] `src/KeePassKeyWin.Provider/src/ipc/mod.rs` — JSON-RPC 2.0 pipe client, exponential backoff, `VaultLocked`/`NoCredentials`/`ClientUnauthorized` error mapping
- [x] `src/KeePassKeyWin.Provider/src/ctap/mod.rs` — typed params/results for all five RPC methods, `rp_id_hash`, `make_credential_to_rpc`
- [x] `src/main.rs` CLI — `smoke` and `make-credential` subcommands (create→list→sign→delete flow)
- [x] 23 unit tests passing on Linux (IPC round-trip via Unix socket, CTAP serde, error mapping)

### Phase 2b — COM bindings + MSIX manifest ✓ (Linux build; pending Windows)

- [x] `src/com/types.rs` — `#[repr(C)]` ABI-compatible types: `WebauthNPluginOperationRequest/Response`, `WebauthNPluginCancelOperationRequest`, `PluginLockStatus`, `Guid`
- [x] `src/com/server.rs` — hand-rolled `IPluginAuthenticatorVtbl` vtable; `IPluginAuthenticatorImpl` with atomic ref-count + `Arc<Mutex<State>>`; `make_credential`, `get_assertion`, `cancel_operation`, `get_lock_status` dispatch
- [x] `src/com/dll.rs` — `ClassFactory` + `DllGetClassObject`, `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer` exports
- [x] `appx/Package.appxmanifest` — `MinVersion="10.0.26100.0"`, `rescap:runFullTrust`, `com:InProcessServer` with CLSID `5c6840dc-…`, STA threading model
- [x] `.cargo/config.toml` — `lld-link` linker + xwin SDK paths for `x86_64-pc-windows-msvc` cross-compilation
- [x] `idl/pluginauthenticator.h` — reference header transcribed from Microsoft WebAuthn SDK

**Phase 2.1 — MSIX install** (scripts wired; validated on Windows 11 via `.\scripts\validate-phase2.ps1`):
- [x] `cargo xwin build --target x86_64-pc-windows-msvc --release` — DLL + EXE build cleanly (cross-compiled from WSL2)
- [x] `makeappx pack` + `signtool sign` — `scripts/build-msix.ps1` + `scripts/sign-msix.ps1` with publisher/cert-subject pre-check
- [x] Sideload MSIX → `scripts/install-msix.ps1` asserts `Get-AppxPackage` Publisher / Version / PackageFamilyName

**Phase 2.2 — Activation + COM live path** ✅ GREEN 2026-04-18 (KeePassKeyWin visible in Settings → Accounts → Passkeys):

> **Architecture pivot (Session 3):** out-of-process activation via `com:ExeServer` / `CLSCTX_LOCAL_SERVER`, not in-proc via DLL. The in-proc code path (`src/com/dll.rs`) was deleted; class factory + IClassFactory vtable live in `keepasskeywin-provider.exe`'s `main()` under `-PluginActivated`.
>
> **ABI archaeology (Session 4):** The locally-installed SDK 10.0.26100.0 declares a truncated 7-field `WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS`. The runtime DLL on build 26200.8037 implements the 9-field 72-byte shape from SDK 10.0.26100.7175 (the version PasskeyManager declares). Four wrong guesses (7-field with null logos, 7-field with non-null logos, 9-field with inline 16-byte GUID, 9-field with pointer GUID and string CLSID) before the research agent extracted the authoritative header from NuGet. `rclsid` is `REFCLSID` = 8-byte pointer-to-GUID; the two `SupportedRpIds` fields at the tail were being read from stack garbage and crashed (STATUS_ACCESS_VIOLATION) when that garbage looked like a non-zero count.

- [x] Add `-PluginActivated` arg handling in `keepasskeywin-provider.exe` `main()` — registers class factory via `CoRegisterClassObject(REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED)`, enters STA, pumps messages
- [x] Move `IPluginAuthenticatorImpl` / vtable into the EXE binary; delete `src/com/dll.rs` entirely
- [x] `WebAuthNPluginAddAuthenticator` call — `keepasskeywin-provider.exe register` + `unregister` subcommands, runtime-loaded via LoadLibraryW/GetProcAddress (EXPERIMENTAL_ symbol is NOT in webauthn.lib's import table)
- [x] **Verify Settings → Accounts → Passkeys → Advanced options lists the provider** (hard gate — cleared 2026-04-18)
- [x] STA re-entrancy: `sta_block_on()` replaces `runtime.block_on` in the authenticator dispatch; uses `CoWaitForMultipleHandles` so the message pump keeps running during pipe I/O
- [x] Tighten `WebauthNPluginOperationResponse` offset assertions (now `== 16` exact on x64, with `offset_of!` assertions)
- [x] Drop the `keepasskeywin_provider.dll` cdylib — removed from Cargo.toml `crate-type`, build-msix.ps1, validate-phase2.ps1; `src/com/dll.rs` deleted
- [ ] Named-pipe connection test with live KeePass plugin under the out-of-proc EXE (deferred to Phase 2.3 — requires a scriptable C# pipe server stub)
- [ ] Runtime vtable validation: attach WinDbg to activated EXE, confirm slot 3 = MakeCredential, slot 6 = GetLockStatus (deferred — run if Phase 3 browser flow debugging needs it)

## Phase 3 — End-to-end `MakeCredential` ✅ GREEN 2026-04-18

Live browser E2E PASSED on Win11 25H2 build 26200.8037. Registration at webauthn.io via KeePassKeyWin succeeds end-to-end.

- [x] CBOR decode of `MakeCredential` request — hand-rolled `CborReader` in `src/KeePassKeyWin.Core/Cbor/CborReader.cs` mirroring existing `CborWriter`; rejects indefinite-length / tags / floats; length-bomb guard. Session 6 fix: `SkipValue` tolerates MT7 simple values (false/true/null/undefined) so we can ignore `options: {rk:true, uv:true}` — webauthn.io sends them and we were rejecting.
- [x] authData construction with real UV flag — `AuthDataBuilder.Build/BuildAssertion` now require explicit `userVerified` (no default); flag propagated from Rust-side UV result
- [x] Windows Hello UV via `WebAuthNPluginPerformUserVerification` — dynamic LoadLibrary binding (stable-name-first, EXPERIMENTAL_ fallback), called inline on STA, response freed on every path, E_ABORT propagated on user cancel. Session 6 fix: `WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST.rguidTransactionId` is `REFGUID` (pointer), not inline GUID — struct 40→32 bytes.
- [x] `keepasskeywin.makeCredentialRaw` IPC round-trip — new JSON-RPC method carries `{cbor, uv}`; returns `{cbor}` CTAP2 attestation object with **integer keys** `{1:"none", 2:authData, 3:{}}` per CTAP 2.1 §6.1. Error codes: `-32030 UnsupportedAlgorithm`, `-32031 CredentialExcluded`. Session 6 fix: Rust sidecar now performs `keepasskeywin.hello` handshake (PFN + HKCU nonce) on COM activation; plugin's `RegistryNonceStore.ConsumeNonce` rotates the nonce so subsequent activations can authenticate.
- [x] webauthn.io from Edge: register succeeds, server-side attestation verification passes — ✅ 2026-04-18 on Win11 build 26200.8037. Credential persisted to vault; site confirms registration.
- [x] `cmd_register` idempotent refresh on NTE_EXISTS — remove+retry wraps the plugin-registration API whose documented "update on re-register" isn't actually implemented by the runtime.

**Deferred to Phase 3.1 (polish):**
- [ ] Switch `keepasskeywin-provider.exe` to `#![windows_subsystem = "windows"]` so the console stops flashing during COM activation. Kept as console for now because the `[activate]` / `[dispatch]` `eprintln!` breadcrumbs are load-bearing for live debugging.
- [ ] Demote `eprintln!` breadcrumbs to `tracing::debug` once stable.

## Phase 4 — End-to-end `GetAssertion` ✅ GREEN 2026-04-19

Live browser E2E PASSED on Win11 25H2 build 26200.8037. Login at webauthn.io via KeePassKeyWin succeeds end-to-end — passkey picker shows the KeePassKeyWin credential, Windows Hello UV fires, assertion signs, server-side verification accepts the login.

- [x] `WebAuthNPluginAuthenticatorAddCredentials` FFI — dynamic-load binding + `WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS` struct (64B, x64 layout asserted) in `src/KeePassKeyWin.Provider/src/com/webauthnplugin_ext.rs`; called from `dispatch_operation`'s MakeCredential success arm; best-effort (logs and continues on failure so webauthn.io registration isn't held hostage to picker visibility)
- [x] `keepasskeywin.makeCredentialRaw` response extended with 6 fields (`credentialIdB64Url`, `rpId`, `rpName`, `userHandleB64Url`, `userName`, `userDisplayName`) — Rust sidecar decodes and populates `WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS`
- [x] `keepasskeywin.getAssertionRaw` IPC handler — CTAP2 §6.2 request parse (integer-keyed top + text-keyed `PublicKeyCredentialDescriptor` in allowList), credential selection from allowList, ES256 DER-signed assertion, CTAP2-integer-keyed response with text-keyed nested `credential` descriptor (same shape-discipline as Phase 3's attestationObject — hex-shape canary test added)
- [x] `CborReader.ReadBool()` for CTAP2 `options` map (MT7 simple values 0xF4/0xF5)
- [x] `PasskeyRecord.SignCount` + `IPasskeyStore.IncrementSignCount` — thread-safe read-increment-write with **synchronous `PwDatabase.Save`** (critical: prevents signCount-rollback replay after KeePass-close-without-save, which would get the user permanently locked out at the RP per WebAuthn §6.1.1 cloned-authenticator clause)
- [x] HRESULT mapping: `ClientError::NoCredentials` → `NTE_NOT_FOUND (0x80090011)` (empty allowList / no allowList match)
- [x] `AuthDataBuilder.BuildAssertion(rpId, userVerified, signCount)` — extended from Phase 3's hardcoded-zero signCount; 37-byte assertion authData with explicit UV propagation
- [x] Linux CI green: `cargo test --all-targets` 54 passing; `dotnet test` 220 passing (up from 183); `cargo xwin build --target x86_64-pc-windows-msvc --release` clean
- [x] webauthn.io from Edge: login succeeds, signature verifies server-side — ✅ 2026-04-19 on Win11 build 26200.8037
- [x] Windows Settings picker + webauthn.io picker both list the KeePassKeyWin credential after MakeCredential (AddCredentials OS-side state confirmed)
- [x] Pipe-busy fix (`ea5cbd1`): `cf_create_instance` shares one `KeePassKeyWinAuthenticatorState` Arc process-wide — webauthn.dll's per-operation `CoCreateInstance` no longer causes `ERROR_PIPE_BUSY` when Object 1 (MakeCredential) still holds the pipe while Object 2 (GetAssertion) activates

**MVP-scope punts (explicit, documented for Phase 4.1 follow-up):**
- Discoverable-credential / usernameless flow (empty allowList) returns `NoCredentials`/`NTE_NOT_FOUND`. webauthn.io's default login sends a non-empty allowCredentials, so this doesn't block the E2E gate — only the "usernameless" toggle.
- `RemoveCredentials` / `GetAllCredentials` / `RemoveAllCredentials` FFIs not bound. No vault↔OS reconciliation at startup (so a vault-side delete leaves an orphan in the Windows picker until next `AddCredentials` for a different cred). Flag: consider binding + startup reconciliation for Phase 4.1.
- `options.up=false` → `InvalidOption` (-32041), falls through to E_FAIL on Rust side (unmapped). Implausible in real flows per DA review.
- UV trust boundary: Rust sidecar's `PerformUserVerification` success is propagated to plugin as a trusted `uv: true` JSON-RPC flag (same model as Phase 3). If future hardening is required, derive the UV bit from the Windows UV-response struct rather than Rust's say-so.

## Phase 5 — Polish + RS256 + deferred hardening

- [x] RS256 (COSE `-257`) algorithm support — ES256 preferred via tiebreaker; RS256 selectable when RP excludes ES256; both advertised in `authenticatorGetInfo`
- [ ] Plugin UI: list / delete passkeys from inside KeePass
- [ ] Sidecar confirmation UI when KeePass is minimized
- [ ] `credProps` extension
- [x] **⚠ Important — deferred from Phase 2.2**: plugin-side verification of `WEBAUTHN_PLUGIN_OPERATION_REQUEST.pbRequestSignature` against the op-signing public key. Landed in `67a38ae` (enforcement) + `9d96aef` (cancel-op fix); live-validated at webauthn.io on 2026-04-23 with bypass env var unset at Process/User/Machine scope. Implementation deviates from the original brief: key is runtime-fetched via `WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)` and cached per-process (fail-closed `OnceLock`) rather than persisted in HKCU/LocalState — rationale in `src/KeePassKeyWin.Provider/src/com/request_sig.rs` module docs. Emergency bypass: `KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY=1`. `cancel_operation` intentionally skips the gate, matching Microsoft's PasskeyManager sample.

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

## Open-source readiness follow-ups (2026-04-19)

Captured after the pre-open-source audit. None block making the repo public, but all are worth doing before a broader announcement (e.g., Hacker News, KeePass plugin-list listing).

- [x] **Trademark search** — Completed 2026-04-19. Original name "PassKee" carried a YELLOW confusing-similarity risk against **BearMinds AB's "PassKeep"** (EUTM 019224407, registered 2025-11-12, classes 9 + 42, active EU-wide incl. Italy). No USPTO/WIPO/UIBM direct collision, but the EU overlap was enough to trigger a preemptive rebrand to **KeePassKeyWin** before public announcement. FIDO Alliance holds no "PASSKEY" word mark (only the icon + "FIDO"), so the `passkey` suffix itself carries no trademark risk.
- [x] **CI** — `.github/workflows/ci.yml` runs `dotnet test KeePassKeyWin.sln` + `cargo test --all-targets` on Ubuntu for push/PR. Windows cross-compile gate (`cargo xwin build --release`) deferred.
- [x] **`CONTRIBUTING.md`** — contributor guide at repo root. Covers host-OS matrix (Windows full / Linux-WSL tests + `cargo xwin` / macOS tests only), toolchain (.NET 8 + Rust stable + Windows SDK), build + test commands mirroring CI, live-validation gate for runtime PRs, style/commits/PR expectations, and a landmines section flagging CTAP2 int-vs-text CBOR keys, synchronous `signCount` save, `WEBAUTHN_PLUGIN_*` struct offsets, and Settings-UI non-visibility.
- [x] **`CODE_OF_CONDUCT.md`** — Contributor Covenant v2.1 reference, reporting address matches `SECURITY.md`.
- [ ] **`CHANGELOG.md`** — map phases to user-visible changes; low priority until the first tagged release.
- [x] **`.github/dependabot.yml`** — Cargo + NuGet (all 5 csprojs) + github-actions; grouped PRs, weekly (actions monthly).
- [x] **GitHub issue + PR templates** — `.github/ISSUE_TEMPLATE/bug_report.yml`, `feature_request.yml`, `.github/PULL_REQUEST_TEMPLATE.md`.
- [ ] **Screenshot / demo** — a single screenshot of the Windows passkey picker listing a KeePassKeyWin credential is the single highest-signal trust-builder for adoption.
- [ ] **MSIX publisher subject placeholder** — `CN=Marco Lodini, O=KeePassKeyWin, C=IT` in `Package.appxmanifest` and `ensure-dev-cert.ps1` needs to match the real code-signing cert subject once a production cert is obtained. Not a repo-public blocker; a release-engineering gate.
- [ ] **Phase 3.1 polish (already tracked above)** — demote `eprintln!` breadcrumbs to `tracing::debug`, add `#![windows_subsystem = "windows"]`. Worth doing before the first signed MSIX ships, not before the repo goes public.
