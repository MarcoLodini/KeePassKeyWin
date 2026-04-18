//! Runtime-loaded bindings for the EXPERIMENTAL_ WebAuthN plugin-provider
//! registration APIs.
//!
//! These three functions are exported from `webauthn.dll` (Windows 11 SDK
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

#![cfg(windows)]

use std::sync::OnceLock;

use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::com::types::{
    Guid,
    WebauthnPluginAddAuthenticatorOptions,
    WebauthnPluginAddAuthenticatorResponse,
};

// ── Function pointer types ────────────────────────────────────────────────────

type PfnAdd = unsafe extern "system" fn(
    *const WebauthnPluginAddAuthenticatorOptions,
    *mut *mut WebauthnPluginAddAuthenticatorResponse,
) -> HRESULT;

/// Remove takes `REFCLSID` (const GUID*) per webauthnplugin.h. An earlier
/// version of this binding used `*const u16` (LPCWSTR) matching Marco's
/// outdated 10.0.26100.0 SDK header — that SDK lagged the runtime ABI.
type PfnRemove = unsafe extern "system" fn(*const Guid) -> HRESULT;

type PfnFreeResponse = unsafe extern "system" fn(*mut WebauthnPluginAddAuthenticatorResponse);

// ── Cached bindings ───────────────────────────────────────────────────────────

struct WebauthnBindings {
    add:  PfnAdd,
    remove: PfnRemove,
    free_response: PfnFreeResponse,
    /// Which symbol name was resolved for `add` — diagnostic only. Stored
    /// as a static string so we can report it even after the call crashes.
    add_symbol_name: &'static str,
}

// HMODULE is just a handle; sharing across threads is fine because we never
// call FreeLibrary (process-lifetime load).
unsafe impl Send for WebauthnBindings {}
unsafe impl Sync for WebauthnBindings {}

static BINDINGS: OnceLock<Result<WebauthnBindings, String>> = OnceLock::new();

/// Load webauthn.dll and resolve the three plugin-registration entry
/// points. Each symbol is looked up under its stable name first
/// (`WebAuthNPlugin…`, available on Win11 25H2 + SDK 10.0.26100.7175+),
/// with a fallback to the legacy `EXPERIMENTAL_` name. Cached — subsequent
/// calls return the same result. On failure every subsequent call returns
/// the same error; no retry.
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

        Ok(WebauthnBindings {
            add:             unsafe { std::mem::transmute::<_, PfnAdd>(add) },
            remove:          unsafe { std::mem::transmute::<_, PfnRemove>(rem) },
            free_response:   unsafe { std::mem::transmute::<_, PfnFreeResponse>(free) },
            add_symbol_name: add_name,
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
