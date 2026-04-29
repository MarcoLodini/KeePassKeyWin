# Changelog

All notable changes to KeePassKeyWin are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) once 1.0 is cut.

KeePassKeyWin is pre-1.0. Until the first tagged release, every change rolls
into `[Unreleased]`. See `docs/PLAN.md` for the granular live implementation
log (commits, validation dates, deferred items); this file is the
human-readable summary aimed at downstream packagers, security reviewers, and
people upgrading mid-development.

## [Unreleased]

### Security

- **Plugin verifies `pbRequestSignature` over `SHA-256(pbEncodedRequest)`
  independently** for every `makeCredentialRaw` / `getAssertionRaw` dispatch,
  using the Windows op-signing public key cached from the IPC handshake
  (Phase 5.UV.2). Plugin is the **sole verifier** since the sidecar-side gate
  was removed in 5.UV.5 — see *Removed* below.
- **Plugin verifies the UV response signature** for v2-tier dispatches against
  the same op-signing public key, accepting both IEEE P1363 and DER ECDSA-Sig
  formats (Phase 5.UV.4). For v1-tier dispatches (where the response signature
  covers no caller-supplied buffer and cannot be verified cryptographically),
  the plugin shows a once-per-process Yes/No confirmation dialog; cached for
  the plugin-process lifetime, exception-safe (no sticky-deny on dialog throws).
- **`opSignPublicKeyB64` is required in the IPC handshake** since 5.UV.4. A
  hello frame missing or malformed-base64 in this field is rejected with
  `-32602 InvalidParams` and the connection is terminated. The sidecar
  returns `Err` from `handshake()` rather than sending hello without the key.
- **PII gating for plugin-side diagnostic logs** (5.UV.6). Lines that
  interpolate user-supplied identifiers (RP ID, user name) are tagged
  `LogTier.Pii` in `KeePassKeyWin.Core.Diagnostics.TraceLogger` and are
  suppressed unless `KEEPASSKEYWIN_LOG_PLUGIN_PII=1` is set. The two PII
  gates (plugin / sidecar) are independent and both must be set during
  diagnosis to capture both sides — see `WINDOWS_VALIDATION.md` § Step 6c.

### Added

- IPC field `pbRequestSignatureB64` on `makeCredentialRaw` / `getAssertionRaw`
  carrying the raw `WEBAUTHN_PLUGIN_OPERATION_REQUEST.pbRequestSignature`
  bytes (Phase 5.UV.2). Plugin-side verification gate documented in
  `docs/IPC_PROTOCOL.md` and `docs/ARCHITECTURE.md`.
- IPC fields `uvSignatureB64` (the opaque
  `WebAuthNPluginPerformUserVerification(2)` response) and `uvBindingTier`
  (`"v2_stable" | "v2_experimental" | "v1"`, controls which gate branch
  runs) on `makeCredentialRaw` / `getAssertionRaw` (Phase 5.UV.3 / 5.UV.4).
- `UvFallbackPrompt` Core class with cached-decision latch for v1-tier UV
  dispatches (Phase 5.UV.4). Concurrent v1 dispatches block on the first
  decision; the latch only closes on a real Yes/No (exceptions release it
  unlatched so the next operation re-asks).
- `EcdsaVerifier.VerifyAcceptingEitherFormat` — verifies an ECDSA-P256
  signature in either IEEE P1363 (64-byte) or DER `ECDSA-Sig-Value` form,
  for robustness against Windows API format drift between
  `PerformUserVerification` versions (Phase 5.UV.4).
- Sidecar `tracing-subscriber::EnvFilter` integration (Phase 5.UV.4.5).
  `KEEPASSKEYWIN_LOG_LEVEL` (renamed from `RUST_LOG` in 5.UV.6 — see
  *Changed*) is honoured on both the file route (`KEEPASSKEYWIN_LOG_FILE`)
  and the stderr route. Per-activation / per-dispatch breadcrumbs survive
  the default `info` filter.
- Sidecar log-filter parse warnings are now captured to the live tracing
  sink (Phase 5.UV.6). A typo in `KEEPASSKEYWIN_LOG_LEVEL` keeps every
  parseable directive (lossy semantics) and emits a `WARN log_filter:
  KEEPASSKEYWIN_LOG_LEVEL: rejected directive "<bad>": <error>` line into
  the file route, instead of the closed stderr handle the
  `windows_subsystem = "windows"` build inherits during COM activation.
- `docs/SECURITY.md` § "Trust model" — explicit call-out of what the
  plugin verifies independently vs sources from the sidecar (Phase 5.UV.6).
- `docs/ARCHITECTURE.md` § "Trust boundaries and signature verification"
  — fuller treatment of both gates, op-sign-pubkey provenance, and the
  5.UV.5 / 5.UV.7 trade-offs (Phase 5.UV.6).
- **CI: Windows-target compile + clippy gates** (Phase 5.UV.9.7, also
  closes the 5.UV.9.5 tail). New `windows-cross` job in
  `.github/workflows/ci.yml` runs `cargo xwin clippy --target
  x86_64-pc-windows-msvc --release --all-targets -- -D warnings`
  followed by `cargo xwin test --no-run --target
  x86_64-pc-windows-msvc --all-targets` on the Ubuntu runner. The test
  step uses `--no-run` (no Windows runner is available) — the goal is
  to catch the class of regression that hid the `coset` dev-dep gap in
  the `make_credential_cbor` `#[cfg(windows)] + #[cfg(test)]` fixture
  for years (Linux CI cfg's it out; `cargo xwin build` doesn't compile
  tests). The clippy step makes the Windows-target lint hygiene that
  5.UV.9.5 just stabilised a permanent gate. Job uses
  `taiki-e/install-action` for cargo-xwin (prebuilt binary), pins
  `XWIN_ACCEPT_LICENSE=1` for non-interactive MSVC SDK EULA, and caches
  `~/.cache/cargo-xwin` (~600MB SDK download) separately from
  `target/` so the cold-start cost is paid once.

### Changed

- **Sidecar log-filter env var renamed** `RUST_LOG` → `KEEPASSKEYWIN_LOG_LEVEL`
  (Phase 5.UV.6). Same `tracing` directive grammar; new name is unambiguous in
  `Get-ChildItem Env:KEEPASSKEYWIN_*` dumps. No back-compat alias — pre-1.0
  software, single user. Migration: `setx /M RUST_LOG ""` and re-set under
  the new name.
- Sidecar swapped `WebAuthNPluginPerformUserVerification` (v1) for the
  experimental v2 entrypoint where available
  (`EXPERIMENTAL_WebAuthNPluginPerformUserVerification2` →
  `WebAuthNPluginPerformUserVerification2`), with load-time triple-fallback
  to v1 on Windows builds where v2 is not exported (Phase 5.UV.3).
- Plugin-side PII-bearing breadcrumbs in `VaultHandler` (`rpId`, `userName`)
  refactored from a single Info-level line to an Info line (no PII) plus a
  Debug-level line (PII) gated by `KEEPASSKEYWIN_LOG_PLUGIN_PII` (Phase 5.UV.6).

### Removed

- **Sidecar-side `verify_request_signature` gate** (Phase 5.UV.5). Deleted
  the `verify_with_ncrypt`, `is_bypass_enabled`, and `verify_request_signature`
  functions and all four sidecar-side verify tests from
  `src/com/request_sig.rs`. The plugin is now the only enforcer for
  request-signature integrity. A latent NCryptVerifySignature bug observed
  in pre-5.UV.5 diagnostics and a `register`-time keypair-desync race are
  both moot — the gate that exposed them is gone.
- **Sidecar-side `KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY` env var** retired
  (Phase 5.UV.5). The emergency bypass is `KEEPASSKEYWIN_SKIP_PLUGIN_SIG_VERIFY=1`
  (plugin-side, dev-only).
- Dead source file `src/KeePassKeyWin.Provider/src/com/mod.rs` deleted (Phase
  5.UV.6). The canonical `com` module has been declared inline in
  `src/lib.rs` via `pub mod com { ... }` since the early sidecar work; the
  `mod.rs` was silently ignored by the Rust resolver.

### Fixed

- **Faithful registry-error messages from `read_handshake_nonce`** (Phase 5.UV.9).
  Surfaced by 5.UV.8's silent-failure-hunter audit: the sidecar's helper that
  reads `HKCU\Software\KeePassKeyWin\HandshakeNonce` collapsed every
  `RegGetValueW` failure mode (key absent, wrong value type, ACL deny, registry
  corruption, buffer too small, malformed UTF-16) to a single `Option::None`,
  which `connect_and_handshake` then logged as `... missing` — wording faithful
  only for the key-absent case. A new cross-platform `RegReadError` enum and a
  pure `lstatus_to_reg_read_error` mapper (Linux-CI tested) classify the failure
  into `NotFound | WrongType { actual_type } | AccessDenied | BufferTooSmall |
  MalformedString | Other(LSTATUS)`, and `connect_and_handshake` maps each
  variant to a distinct `ClientError::InvalidRequest("HKCU\\... <reason>")`
  message, both in the tracing log line and in the returned error string. No
  production behaviour change beyond log/error text accuracy.
- **Windows-target `cargo clippy` is now clean** (Phase 5.UV.9.5).
  Pre-Phase-6 polish: `cargo clippy --target x86_64-pc-windows-msvc --release
  --all-targets` was not gated by CI (which only runs Linux-target clippy +
  `cargo xwin build`) and surfaced 9 deny-by-default `not_unsafe_ptr_arg_deref`
  errors plus 11 warnings across `webauthn_ext.rs`, `request_sig.rs`,
  `server.rs`, `exe_server.rs`. Five public functions that dereference raw
  pointers are now `unsafe fn` with per-parameter `# Safety` doc-comments
  (including the `WebauthnPluginAddAuthenticatorOptions.rclsid` REFCLSID-trap
  warning that the v1 register path lacked but `perform_user_verification_2`
  documents); call sites in `exe_server.rs` and `server.rs` are wrapped in
  explicit `unsafe { ... }` blocks with inline SAFETY rationales. Five
  `transmute::<_, Pfn...>` calls have explicit source types; four
  `b"...\0".as_ptr()` byte-strings are `c"...".as_ptr().cast::<u8>()`
  (`PCSTR` wraps `*const u8`, `CStr::as_ptr` returns `*const c_char`); idiomatic
  `iter().any() → contains()` and `for i in 0..n` → `.iter().enumerate()`
  rewrites. While auditing, found a hidden Windows-target test compile error:
  the `make_credential_cbor` test fixture used `coset::iana::Algorithm::ES256`,
  but `coset` was only a transitive dep of `passkey-types` — it failed to
  resolve on `cargo clippy --target x86_64-pc-windows-msvc`. Linux CI cfg's
  the `#[cfg(windows)]` fixture out and `cargo xwin build` doesn't compile
  tests, so the gap had been silent. Added `coset = "0.3"` as a dev-dep,
  pinned to match the resolved 0.3.8.
- **Sidecar inline stale-pipe retry** (Phase 5.UV.8). When the KeePass plugin
  process restarts (close/reopen, update, lock-cycle, crash) while the
  sidecar is still alive in the COM ExeServer idle window, the cached pipe
  handle in process-wide `SHARED_STATE` goes stale; the next dispatch's
  pipe write produced `Io(BrokenPipe) → E_FAIL`, surfacing as a generic
  "Something went wrong" on the user's first WebAuthn click. The sidecar
  dispatch helper now classifies the error, drops the dead pipe,
  reconnects + re-runs the `keepasskeywin.hello` handshake, and retries
  the same JSON-RPC method with the same params (the UV signature
  collected earlier in the dispatch is reused, so no second Windows Hello
  prompt). Exactly one retry per dispatch — if reconnect/re-handshake
  also fails, `SHARED_STATE` is cleared so the next COM activation starts
  fresh and the dispatch returns `E_FAIL`. Applied to all four IPC methods
  that go over the cached pipe (`MakeCredential`, `GetAssertion`,
  `CancelOperation`, `GetLockStatus`) — same UX axis on which v1 (clear-
  and-fail) was rejected. On `CancelOperation` this also closes a latent
  self-poisoning case where a stale-pipe error would have been silently
  stored back into the cached state and surfaced on the next real
  dispatch. Workaround for users on pre-5.UV.8 sidecars was
  `Stop-Process -Name keepasskeywin-provider -Force` before each KeePass
  restart; that workaround is no longer needed.
- **Call-time v2 → v1 fallback on `E_NOTIMPL`** (Phase 5.UV.7). On Windows 11
  24H2 build 26100.6725+ (KB5068861), `WebAuthNPluginPerformUserVerification2`
  resolves at load time but is a forward-declared stub returning `E_NOTIMPL`.
  The 5.UV.3 load-time triple-fallback was insufficient — picking the
  resolved stable name committed us to a doomed call. The sidecar now caches
  an `AtomicBool` per process, sets it on the first `E_NOTIMPL`, and
  short-circuits the v2 attempt for all subsequent dispatches in that
  process, falling through to v1 in the same dispatch. Only `E_NOTIMPL`
  poisons the cache (`E_ABORT`, `E_FAIL`, `E_INVALIDARG` leave it false).
  Cache is per-process — a future Windows update shipping the real v2 is
  adopted automatically on next COM activation.
