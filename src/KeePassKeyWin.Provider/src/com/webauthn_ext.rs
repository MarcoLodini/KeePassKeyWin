//! Runtime-loaded bindings for the EXPERIMENTAL_ WebAuthN plugin-provider
//! registration APIs.
//!
//! These functions are exported from `webauthn.dll` (Windows 11 SDK
//! 10.0.26100.0+) but **are NOT present in `webauthn.lib`'s import table**.
//! Microsoft's convention for unstable `EXPERIMENTAL_` APIs is to ship the
//! DLL exports but withhold the import-lib entries. `#[link(name = "webauthn")]`
//! therefore fails at link time with "undefined symbol" — we MUST load the
//! functions dynamically via `LoadLibraryW` + `GetProcAddress`.
//!
//! The `EXPERIMENTAL_` prefix is load-bearing on the symbol names — Microsoft
//! uses it to mark unstable APIs whose shape may change between SDK
//! revisions. Our Rust types (in `com::types`) drop the prefix for
//! readability; the `GetProcAddress` lookup strings keep it verbatim.
//!
//! Function pointers are cached in a `OnceLock` — one `LoadLibraryW` per
//! process; subsequent `cmd_register` / `cmd_unregister` invocations reuse
//! the same handle.
//!
//! ## Phase 5.UV.3: PerformUserVerification v2 triple-fallback
//!
//! The v2 UV entrypoint (`EXPERIMENTAL_WebAuthNPluginPerformUserVerification2`)
//! extends the v1 request struct with a buffer-to-sign so the UV response
//! signature can be independently verified plugin-side. The binding resolves
//! with three-level fallback:
//!
//!   1. `WebAuthNPluginPerformUserVerification2` — stable name (may not exist yet)
//!   2. `EXPERIMENTAL_WebAuthNPluginPerformUserVerification2` — ships on 24H2
//!   3. `WebAuthNPluginPerformUserVerification` — v1 guaranteed fallback
//!
//! Which tier resolved is returned alongside every UV call result so the IPC
//! layer can forward it to the plugin (for the 5.UV.4 fallback-warning dialog).
//!
//! ## Debug override: `KEEPASSKEYWIN_FORCE_UV_V1=1`
//!
//! The triple-fallback lookup makes the v1 path unreachable on any Windows
//! build that exports a `_2` symbol — i.e. every machine on 24H2 26100.6725+.
//! For acceptance-testing the plugin's v1-fallback dialog (5.UV.4) on a real
//! machine, set `KEEPASSKEYWIN_FORCE_UV_V1=1` before activating the sidecar:
//! the v2 lookup is skipped and `WebAuthNPluginPerformUserVerification` (v1)
//! resolves for every dispatch. See `com::uv_override` for the helper.

#![cfg(windows)]

use std::sync::OnceLock;

use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::com::types::{
    Guid,
    WebauthnPluginAddAuthenticatorOptions,
    WebauthnPluginAddAuthenticatorResponse,
    WebauthnPluginUserVerificationRequest,
    WebauthnPluginUserVerificationRequest2,
};

// ── Function pointer types ────────────────────────────────────────────────────

type PfnAdd = unsafe extern "system" fn(
    *const WebauthnPluginAddAuthenticatorOptions,
    *mut *mut WebauthnPluginAddAuthenticatorResponse,
) -> HRESULT;

/// Remove takes `REFCLSID` (const GUID*) per webauthnplugin.h. An earlier
/// version of this binding used `*const u16` (LPCWSTR) matching the
/// outdated 10.0.26100.0 SDK header — that SDK lagged the runtime ABI.
type PfnRemove = unsafe extern "system" fn(*const Guid) -> HRESULT;

type PfnFreeResponse = unsafe extern "system" fn(*mut WebauthnPluginAddAuthenticatorResponse);

/// `WebAuthNPluginPerformUserVerification` / `EXPERIMENTAL_` variant (v1).
///
/// Signature from PasskeyManager sample `DelayLoad.h` lines 159-167 and
/// `PluginAuthenticatorImpl.cpp` lines 266-296 (Win11 SDK 10.0.26100.x+):
///   HRESULT WebAuthNPluginPerformUserVerification(
///     PCWEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST pPluginUserVerification,
///     DWORD* pcbResponse,
///     PBYTE* ppbResponse
///   );
///
/// Called inline on the STA thread — NOT via sta_block_on. Windows pumps
/// its own dialog messages while the UV prompt is displayed.
type PfnPerformUv = unsafe extern "system" fn(
    *const WebauthnPluginUserVerificationRequest,
    *mut u32,       // pcbResponse (OUT)
    *mut *mut u8,   // ppbResponse (OUT)
) -> HRESULT;

/// `WebAuthNPluginPerformUserVerification2` / `EXPERIMENTAL_` variant (v2).
///
/// Extends v1 with a buffer-to-sign (`cb_buffer_to_sign` + `pb_buffer_to_sign`)
/// so the UV response signature covers a sidecar-provided digest. Callers
/// compute `SHA-256(pbEncodedRequest)` and pass the 32-byte digest as the
/// buffer; the Windows runtime signs it and returns the opaque signature via
/// `ppbResponse`.
///
/// Same calling convention as v1 except the request struct is
/// [`WebauthnPluginUserVerificationRequest2`] (48 bytes vs 32 bytes).
type PfnPerformUv2 = unsafe extern "system" fn(
    *const WebauthnPluginUserVerificationRequest2,
    *mut u32,       // pcbResponse (OUT)
    *mut *mut u8,   // ppbResponse (OUT)
) -> HRESULT;

/// `WebAuthNPluginFreeUserVerificationResponse` / `EXPERIMENTAL_` variant.
///
/// Frees the heap-allocated UV response buffer returned by both v1 and v2
/// `PerformUserVerification`. Must be called on every exit path after a
/// successful UV call, even if the response bytes are discarded.
type PfnFreeUvResponse = unsafe extern "system" fn(*mut u8);

// ── UvTier ───────────────────────────────────────────────────────────────────

/// Which Windows entrypoint resolved for `PerformUserVerification`.
///
/// Determined once at first UV call time (lazy, not at hello/startup).
/// Forwarded to the plugin via the `uvBindingTier` IPC field on every UV
/// dispatch so the plugin can:
///   - In 5.UV.4: know whether UV-signature verification is possible (`V1`
///     means the v2 buffer-to-sign handshake didn't happen — plugin cannot
///     verify UV sig; shows fallback-warning dialog once per process).
///   - In 5.UV.5+: use the tier for audit/telemetry.
///
/// Stringly-typed in IPC by design — cheap forward-compat if Microsoft
/// stabilises the `_2` form or adds a `_3` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvTier {
    /// `WebAuthNPluginPerformUserVerification2` resolved (stable name —
    /// may not exist on current 24H2 builds; coded for future stabilisation).
    V2Stable,
    /// `EXPERIMENTAL_WebAuthNPluginPerformUserVerification2` resolved.
    /// This is the tier that resolves on Windows 11 24H2 build 26100.6725+
    /// (KB5068861, Nov 2025) at time of writing.
    V2Experimental,
    /// Only `WebAuthNPluginPerformUserVerification` (v1) resolved.
    /// The UV response signature is still returned by Windows but was NOT
    /// produced using the buffer-to-sign path — plugin-side verification
    /// requires the v2 path and must be skipped (shown as dialog warning).
    V1,
}

impl UvTier {
    /// IPC string value for this tier. Stable across protocol versions.
    ///
    /// Values: `"v2_stable"` | `"v2_experimental"` | `"v1"`.
    pub fn ipc_str(&self) -> &'static str {
        match self {
            UvTier::V2Stable       => "v2_stable",
            UvTier::V2Experimental => "v2_experimental",
            UvTier::V1             => "v1",
        }
    }
}

// ── Cached bindings ───────────────────────────────────────────────────────────

struct WebauthnBindings {
    add:  PfnAdd,
    remove: PfnRemove,
    free_response: PfnFreeResponse,
    /// v1 PerformUV — always resolved; guaranteed fallback.
    perform_uv: PfnPerformUv,
    /// v2 PerformUV — `Some` when stable or experimental `_2` resolved.
    /// `None` means only v1 resolved; use `perform_uv` instead.
    perform_uv_v2: Option<PfnPerformUv2>,
    /// Which tier resolved for the v2 lookup. `V1` when `perform_uv_v2`
    /// is `None`; one of the `V2*` variants when it is `Some`.
    perform_uv_tier: UvTier,
    free_uv_response: PfnFreeUvResponse,
    /// Which symbol name was resolved for `add` — diagnostic only. Stored
    /// as a static string so we can report it even after the call crashes.
    add_symbol_name: &'static str,
    /// Which symbol name was resolved for the v2 PerformUV lookup (or the
    /// v1 fallback name when only v1 resolved). Diagnostic only.
    perform_uv_symbol_name: &'static str,
}

// HMODULE is just a handle; sharing across threads is fine because we never
// call FreeLibrary (process-lifetime load).
unsafe impl Send for WebauthnBindings {}
unsafe impl Sync for WebauthnBindings {}

static BINDINGS: OnceLock<Result<WebauthnBindings, String>> = OnceLock::new();

/// Load webauthn.dll and resolve all plugin entry points. Each symbol is
/// looked up under its stable name first (`WebAuthNPlugin…`, available on
/// Win11 25H2 + SDK 10.0.26100.7175+), with a fallback to the legacy
/// `EXPERIMENTAL_` name. Cached — subsequent calls return the same result.
/// On failure every subsequent call returns the same error; no retry.
///
/// For `PerformUserVerification`, a triple-fallback runs in order:
///   1. `WebAuthNPluginPerformUserVerification2` (stable v2 — may not resolve)
///   2. `EXPERIMENTAL_WebAuthNPluginPerformUserVerification2` (experimental v2)
///   3. `WebAuthNPluginPerformUserVerification` (v1 — always the final fallback)
fn bindings() -> Result<&'static WebauthnBindings, &'static str> {
    let result = BINDINGS.get_or_init(|| {
        let dll_name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
            .map_err(|e| format!("LoadLibraryW(webauthn.dll) failed: {e}"))?;

        let (add, add_name) = get_proc(hmod, &[
            ("WebAuthNPluginAddAuthenticator",              b"WebAuthNPluginAddAuthenticator\0"),
            ("EXPERIMENTAL_WebAuthNPluginAddAuthenticator", b"EXPERIMENTAL_WebAuthNPluginAddAuthenticator\0"),
        ])?;
        let (rem, _) = get_proc(hmod, &[
            ("WebAuthNPluginRemoveAuthenticator",              b"WebAuthNPluginRemoveAuthenticator\0"),
            ("EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator", b"EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator\0"),
        ])?;
        let (free, _) = get_proc(hmod, &[
            ("WebAuthNPluginFreeAddAuthenticatorResponse",              b"WebAuthNPluginFreeAddAuthenticatorResponse\0"),
            ("EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse", b"EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse\0"),
        ])?;

        // v1 PerformUV — required (guaranteed fallback).
        let (perform_uv_raw, _) = get_proc(hmod, &[
            ("WebAuthNPluginPerformUserVerification",              b"WebAuthNPluginPerformUserVerification\0"),
            ("EXPERIMENTAL_WebAuthNPluginPerformUserVerification", b"EXPERIMENTAL_WebAuthNPluginPerformUserVerification\0"),
        ])?;

        // v2 PerformUV — optional; triple-fallback in tier order.
        // try_get_proc returns None without error when no name resolves.
        // Debug override: KEEPASSKEYWIN_FORCE_UV_V1=1 short-circuits to v1
        // so 5.UV.4's fallback-dialog branch can be exercised on builds where
        // _2 would otherwise resolve.
        let (perform_uv_v2_raw, perform_uv_tier, uv2_name): (Option<_>, UvTier, &'static str) =
            if crate::com::uv_override::force_v1_enabled() {
                tracing::warn!(
                    "[uv] KEEPASSKEYWIN_FORCE_UV_V1=1 — skipping v2 lookup; \
                     using v1 (WebAuthNPluginPerformUserVerification) for all dispatches"
                );
                (None, UvTier::V1, "WebAuthNPluginPerformUserVerification")
            } else if let Some(p) = try_get_proc(hmod, b"WebAuthNPluginPerformUserVerification2\0") {
                (Some(p), UvTier::V2Stable, "WebAuthNPluginPerformUserVerification2")
            } else if let Some(p) = try_get_proc(hmod, b"EXPERIMENTAL_WebAuthNPluginPerformUserVerification2\0") {
                (Some(p), UvTier::V2Experimental, "EXPERIMENTAL_WebAuthNPluginPerformUserVerification2")
            } else {
                (None, UvTier::V1, "WebAuthNPluginPerformUserVerification")
            };

        let (free_uv, _) = get_proc(hmod, &[
            ("WebAuthNPluginFreeUserVerificationResponse",              b"WebAuthNPluginFreeUserVerificationResponse\0"),
            ("EXPERIMENTAL_WebAuthNPluginFreeUserVerificationResponse", b"EXPERIMENTAL_WebAuthNPluginFreeUserVerificationResponse\0"),
        ])?;

        Ok(WebauthnBindings {
            add:              unsafe { std::mem::transmute::<_, PfnAdd>(add) },
            remove:           unsafe { std::mem::transmute::<_, PfnRemove>(rem) },
            free_response:    unsafe { std::mem::transmute::<_, PfnFreeResponse>(free) },
            perform_uv:       unsafe { std::mem::transmute::<_, PfnPerformUv>(perform_uv_raw) },
            perform_uv_v2:    perform_uv_v2_raw.map(|p| unsafe { std::mem::transmute::<_, PfnPerformUv2>(p) }),
            perform_uv_tier,
            free_uv_response: unsafe { std::mem::transmute::<_, PfnFreeUvResponse>(free_uv) },
            add_symbol_name:  add_name,
            perform_uv_symbol_name: uv2_name,
        })
    });
    result.as_ref().map_err(|s| s.as_str())
}

/// Which symbol name was resolved for the Add call. `None` until the
/// bindings are initialized; returns a static string matching the exact
/// symbol used thereafter. Diagnostic only — surfaced in the register
/// dump so we can confirm stable-vs-EXPERIMENTAL_ routing post-crash.
pub fn resolved_add_symbol_name() -> Option<&'static str> {
    // Make sure bindings are loaded — calling bindings() does the init.
    let _ = bindings();
    BINDINGS.get().and_then(|r| r.as_ref().ok()).map(|b| b.add_symbol_name)
}

/// Which symbol name was resolved for the PerformUserVerification(2) call.
///
/// Returns the exact symbol string that resolved for the v2 lookup, or the
/// v1 symbol name when only v1 resolved. `None` until bindings are
/// initialized (i.e. until the first [`perform_user_verification_2`] call).
/// Diagnostic only — surfaced in the dispatch log for live-validation triage.
pub fn resolved_perform_uv_symbol_name() -> Option<&'static str> {
    let _ = bindings();
    BINDINGS.get().and_then(|r| r.as_ref().ok()).map(|b| b.perform_uv_symbol_name)
}

/// Try `GetProcAddress` for a single null-terminated symbol name.
/// Returns `Some(fn_ptr)` on success, `None` if the symbol is not exported.
/// Does NOT return an error — used for optional symbols.
fn try_get_proc(hmod: HMODULE, nul_bytes: &[u8]) -> Option<unsafe extern "system" fn() -> isize> {
    unsafe { GetProcAddress(hmod, PCSTR(nul_bytes.as_ptr())) }
}

/// Resolve the first matching symbol from `hmod`, returning the function
/// pointer AND the static string of the name that won. Each entry is a
/// `(display_name, null_terminated_c_bytes)` pair.
fn get_proc(
    hmod: HMODULE,
    names: &[(&'static str, &[u8])],
) -> Result<(unsafe extern "system" fn() -> isize, &'static str), String> {
    for (display, nul_bytes) in names {
        let proc = unsafe { GetProcAddress(hmod, PCSTR(nul_bytes.as_ptr())) };
        if let Some(p) = proc {
            return Ok((p, display));
        }
    }
    let tried: Vec<&str> = names.iter().map(|(d, _)| *d).collect();
    Err(format!(
        "GetProcAddress failed for all of {tried:?} — webauthn.dll on this build does not \
         export any of them. Requires Win11 24H2 26100.6725+ (KB5068861, Nov 2025) with the \
         plugin-passkey provider API."
    ))
}

// ── Public wrappers ───────────────────────────────────────────────────────────

/// Call `EXPERIMENTAL_WebAuthNPluginAddAuthenticator`. On S_OK the caller
/// must free `*pp_response` via [`free_add_authenticator_response`].
pub fn add_authenticator(
    opts: &WebauthnPluginAddAuthenticatorOptions,
    pp_response: *mut *mut WebauthnPluginAddAuthenticatorResponse,
) -> Result<HRESULT, String> {
    let b = bindings().map_err(|s| s.to_string())?;
    Ok(unsafe { (b.add)(opts as *const _, pp_response) })
}

/// Call `WebAuthNPluginRemoveAuthenticator` with a pointer to the CLSID
/// GUID (REFCLSID).
pub fn remove_authenticator(rclsid: *const Guid) -> Result<HRESULT, String> {
    let b = bindings().map_err(|s| s.to_string())?;
    Ok(unsafe { (b.remove)(rclsid) })
}

/// Call `EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse`. Safe to
/// call on a null pointer (skips the FFI call).
pub fn free_add_authenticator_response(p_response: *mut WebauthnPluginAddAuthenticatorResponse) {
    if p_response.is_null() {
        return;
    }
    // If bindings failed to load, we can't free — best-effort leak rather
    // than panic.
    if let Ok(b) = bindings() {
        unsafe { (b.free_response)(p_response) };
    }
}

/// Call the best-available `PerformUserVerification` entrypoint — v2 if it
/// resolved, v1 otherwise — and return `(HRESULT, UvTier)`.
///
/// ## Fallback behaviour
///
/// - **V2Stable / V2Experimental:** Builds a
///   [`WebauthnPluginUserVerificationRequest2`] (48 bytes) with
///   `cb_buffer_to_sign = buffer_to_sign.len()` and
///   `pb_buffer_to_sign = buffer_to_sign.as_ptr()`. The buffer must remain
///   live for the duration of the call (guaranteed when `buffer_to_sign` is
///   a slice of a stack-allocated digest — SHA-256 output is 32 bytes).
/// - **V1:** Builds a [`WebauthnPluginUserVerificationRequest`] (32 bytes);
///   `buffer_to_sign` is **discarded** (v1 has no such field). The Windows
///   runtime still returns an opaque UV response, but the plugin cannot
///   verify it without the buffer-to-sign handshake. The `V1` tier in the
///   returned pair signals this to the caller for IPC forwarding.
///
/// ## REFGUID trap
///
/// `p_txid` is `REFGUID` (pointer), NOT an inline GUID value. Passing an
/// inline GUID shifts every subsequent field by +8 bytes — same crash as
/// the original v1 `STATUS_ACCESS_VIOLATION` (see `types.rs:195-205`).
///
/// ## STA threading
///
/// Called inline on the STA thread — NOT via `sta_block_on`. Windows pumps
/// its own dialog messages while the UV prompt is displayed.
///
/// On `E_ABORT` (0x80004004) the user cancelled. On other HRESULT failures
/// the binding propagates the error code. The caller **MUST** free
/// `*pp_response` via [`free_user_verification_response`] on every exit path
/// after a successful call (non-null `*pp_response`).
pub fn perform_user_verification_2(
    hwnd:            isize,
    p_txid:          *const Guid,
    pwsz_user:       *const u16,
    pwsz_hint:       *const u16,
    buffer_to_sign:  &[u8],
    cb_response:     *mut u32,
    pp_response:     *mut *mut u8,
) -> Result<(HRESULT, UvTier), String> {
    let b = bindings().map_err(|s| s.to_string())?;
    if let Some(pfn_v2) = b.perform_uv_v2 {
        // v2 path: build the 48-byte request with buffer_to_sign.
        let req2 = WebauthnPluginUserVerificationRequest2 {
            hwnd,
            p_transaction_id:  p_txid,
            pwsz_username:     pwsz_user,
            pwsz_display_hint: pwsz_hint,
            cb_buffer_to_sign: buffer_to_sign.len() as u32,
            pb_buffer_to_sign: buffer_to_sign.as_ptr(),
        };
        let hr = unsafe { pfn_v2(&req2 as *const _, cb_response, pp_response) };
        Ok((hr, b.perform_uv_tier))
    } else {
        // v1 fallback: build the 32-byte request; buffer_to_sign discarded.
        let req1 = WebauthnPluginUserVerificationRequest {
            hwnd,
            p_transaction_id:  p_txid,
            pwsz_username:     pwsz_user,
            pwsz_display_hint: pwsz_hint,
        };
        let hr = unsafe { (b.perform_uv)(&req1 as *const _, cb_response, pp_response) };
        Ok((hr, UvTier::V1))
    }
}

/// Call `WebAuthNPluginFreeUserVerificationResponse` (stable) or
/// `EXPERIMENTAL_WebAuthNPluginFreeUserVerificationResponse` (fallback).
///
/// Frees the heap-allocated UV response buffer returned by both v1 and v2
/// `PerformUserVerification`. Safe to call on a null pointer.
/// Should be called on EVERY exit path after a successful UV invocation —
/// including error paths where the UV response is discarded.
pub fn free_user_verification_response(pb_response: *mut u8) {
    if pb_response.is_null() {
        return;
    }
    if let Ok(b) = bindings() {
        unsafe { (b.free_uv_response)(pb_response) };
    }
}
