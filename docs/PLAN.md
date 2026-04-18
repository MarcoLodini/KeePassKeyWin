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
- [x] Harness: standalone C# app that drives Chrome DevTools virtual authenticator via the DevTools Protocol, routing CTAP2 calls to the plugin's JSON-RPC pipe
- [ ] E2E: register + authenticate on [webauthn.io](https://webauthn.io) via the harness through the plugin
- [x] Windows validation runbook (`docs/WINDOWS_VALIDATION.md`) + deploy/smoke scripts (`scripts/`)

## Phase 1 — Plugin skeleton (production-grade)

- [x] OS version gate via `RtlGetVersion` P/Invoke (`OsVersionCheck`); graceful degradation (log + return true, skip pipe)
- [ ] Single-instance pipe (`\\.\pipe\PassKee.<sessionId>`); second-instance detection + warning
- [ ] Handshake: client package family + HKCU nonce verification
- [ ] Full JSON-RPC method surface (hello, createPasskey, listCredentials, signAssertion, deleteCredential, enumerateForSync)
- [x] KeePass Tools menu entry (About, Show Passkeys folder, OS compatibility) + entry editor read-only passkey tab (`MenuEntry`, `PasskeyEntryDecorator`, `AboutDialog`)
- [ ] Unit test suite lifted from Phase 0.5
- [x] `OsVersionCheckTests` (9 tests, pure-logic, runs on Linux net8.0)

## Phase 2 — Provider skeleton (self-signed MSIX, dev machine only)

### Phase 2a — Rust IPC client + CTAP2 types ✓

- [x] `src/PassKee.Provider/src/ipc/mod.rs` — JSON-RPC 2.0 pipe client, exponential backoff, `VaultLocked`/`NoCredentials`/`ClientUnauthorized` error mapping
- [x] `src/PassKee.Provider/src/ctap/mod.rs` — typed params/results for all five RPC methods, `rp_id_hash`, `make_credential_to_rpc`
- [x] `src/main.rs` CLI — `smoke` and `make-credential` subcommands (create→list→sign→delete flow)
- [x] 23 unit tests passing on Linux (IPC round-trip via Unix socket, CTAP serde, error mapping)

### Phase 2b — COM bindings + MSIX manifest ✓ (Linux build; pending Windows)

- [x] `src/com/types.rs` — `#[repr(C)]` ABI-compatible types: `WebauthNPluginOperationRequest/Response`, `WebauthNPluginCancelOperationRequest`, `PluginLockStatus`, `Guid`
- [x] `src/com/server.rs` — hand-rolled `IPluginAuthenticatorVtbl` vtable; `IPluginAuthenticatorImpl` with atomic ref-count + `Arc<Mutex<State>>`; `make_credential`, `get_assertion`, `cancel_operation`, `get_lock_status` dispatch
- [x] `src/com/dll.rs` — `ClassFactory` + `DllGetClassObject`, `DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer` exports
- [x] `appx/Package.appxmanifest` — `MinVersion="10.0.26100.0"`, `rescap:runFullTrust`, `com:InProcessServer` with CLSID `d26bcf6f-…`, STA threading model
- [x] `.cargo/config.toml` — `lld-link` linker + xwin SDK paths for `x86_64-pc-windows-msvc` cross-compilation
- [x] `idl/pluginauthenticator.h` — reference header transcribed from Microsoft WebAuthn SDK

**Phase 2.1 — MSIX install** (scripts wired; validated on Windows 11 via `.\scripts\validate-phase2.ps1`):
- [x] `cargo xwin build --target x86_64-pc-windows-msvc --release` — DLL + EXE build cleanly (cross-compiled from WSL2)
- [x] `makeappx pack` + `signtool sign` — `scripts/build-msix.ps1` + `scripts/sign-msix.ps1` with publisher/cert-subject pre-check
- [x] Sideload MSIX → `scripts/install-msix.ps1` asserts `Get-AppxPackage` Publisher / Version / PackageFamilyName

**Phase 2.2 — Activation + COM live path** ✅ GREEN 2026-04-18 (PassKee visible in Settings → Accounts → Passkeys):

> **Architecture pivot (Session 3):** out-of-process activation via `com:ExeServer` / `CLSCTX_LOCAL_SERVER`, not in-proc via DLL. The in-proc code path (`src/com/dll.rs`) was deleted; class factory + IClassFactory vtable live in `passkee-provider.exe`'s `main()` under `-PluginActivated`.
>
> **ABI archaeology (Session 4):** Marco's locally-installed SDK 10.0.26100.0 declares a truncated 7-field `WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS`. The runtime DLL on build 26200.8037 implements the 9-field 72-byte shape from SDK 10.0.26100.7175 (the version PasskeyManager declares). Four wrong guesses (7-field with null logos, 7-field with non-null logos, 9-field with inline 16-byte GUID, 9-field with pointer GUID and string CLSID) before the research agent extracted the authoritative header from NuGet. `rclsid` is `REFCLSID` = 8-byte pointer-to-GUID; the two `SupportedRpIds` fields at the tail were being read from stack garbage and crashed (STATUS_ACCESS_VIOLATION) when that garbage looked like a non-zero count.

- [x] Add `-PluginActivated` arg handling in `passkee-provider.exe` `main()` — registers class factory via `CoRegisterClassObject(REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED)`, enters STA, pumps messages
- [x] Move `IPluginAuthenticatorImpl` / vtable into the EXE binary; delete `src/com/dll.rs` entirely
- [x] `WebAuthNPluginAddAuthenticator` call — `passkee-provider.exe register` + `unregister` subcommands, runtime-loaded via LoadLibraryW/GetProcAddress (EXPERIMENTAL_ symbol is NOT in webauthn.lib's import table)
- [x] **Verify Settings → Accounts → Passkeys → Advanced options lists the provider** (hard gate — cleared 2026-04-18)
- [x] STA re-entrancy: `sta_block_on()` replaces `runtime.block_on` in the authenticator dispatch; uses `CoWaitForMultipleHandles` so the message pump keeps running during pipe I/O
- [x] Tighten `WebauthNPluginOperationResponse` offset assertions (now `== 16` exact on x64, with `offset_of!` assertions)
- [x] Drop the `passkee_provider.dll` cdylib — removed from Cargo.toml `crate-type`, build-msix.ps1, validate-phase2.ps1; `src/com/dll.rs` deleted
- [ ] Named-pipe connection test with live KeePass plugin under the out-of-proc EXE (deferred to Phase 2.3 — requires a scriptable C# pipe server stub)
- [ ] Runtime vtable validation: attach WinDbg to activated EXE, confirm slot 3 = MakeCredential, slot 6 = GetLockStatus (deferred — run if Phase 3 browser flow debugging needs it)

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
