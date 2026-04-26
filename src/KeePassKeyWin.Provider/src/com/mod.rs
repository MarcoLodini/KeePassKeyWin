//! ⚠ This file is **dead code**. The canonical `com` module is declared
//! inline in `src/lib.rs` via `pub mod com { ... }`, so when Rust's module
//! resolver is told `mod com;` from anywhere it uses the inline body and
//! never reads `mod.rs`. We've left the file present (rather than deleting
//! it outright) only because removing it is its own change with its own
//! review surface — but **do NOT add new `pub mod foo;` declarations here**
//! expecting them to take effect. Add them in `src/lib.rs` inside the inline
//! `pub mod com { ... }` block instead. Slated for removal at 5.UV.6 polish.
//!
//! ── Original (now-stale) header preserved for context ────────────────────
//!
//! COM bindings for IPluginAuthenticator.
//!
//! Microsoft's win32metadata does not yet include IPluginAuthenticator, so we
//! hand-roll the interface declaration using `windows::core` primitives. The
//! vtable layout and IID come directly from
//! `idl/pluginauthenticator.h` (MIDL-generated, from microsoft/webauthn).
//!
//! IID: {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
//! Methods (after IUnknown):
//!   0  MakeCredential(request: PCWEBAUTHN_PLUGIN_OPERATION_REQUEST,
//!                     response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE) -> HRESULT
//!   1  GetAssertion(request: PCWEBAUTHN_PLUGIN_OPERATION_REQUEST,
//!                   response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE) -> HRESULT
//!   2  CancelOperation(request: PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST) -> HRESULT
//!   3  GetLockStatus(lock_status: *mut PluginLockStatus) -> HRESULT

pub mod server;
#[cfg(windows)]
pub mod exe_server;
pub mod types;
#[cfg(windows)]
pub mod webauthn_ext;
