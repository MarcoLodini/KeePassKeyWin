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
    WebauthnPluginAddAuthenticatorOptions,
    WebauthnPluginAddAuthenticatorResponse,
};

// ── Function pointer types ────────────────────────────────────────────────────

type PfnAdd = unsafe extern "system" fn(
    *const WebauthnPluginAddAuthenticatorOptions,
    *mut *mut WebauthnPluginAddAuthenticatorResponse,
) -> HRESULT;

type PfnRemove = unsafe extern "system" fn(*const u16) -> HRESULT;

type PfnFreeResponse = unsafe extern "system" fn(*mut WebauthnPluginAddAuthenticatorResponse);

// ── Cached bindings ───────────────────────────────────────────────────────────

struct WebauthnBindings {
    add:  PfnAdd,
    remove: PfnRemove,
    free_response: PfnFreeResponse,
}

// HMODULE is just a handle; sharing across threads is fine because we never
// call FreeLibrary (process-lifetime load).
unsafe impl Send for WebauthnBindings {}
unsafe impl Sync for WebauthnBindings {}

static BINDINGS: OnceLock<Result<WebauthnBindings, String>> = OnceLock::new();

/// Load webauthn.dll and resolve the three EXPERIMENTAL_ entry points.
/// Cached — subsequent calls return the same result. On failure every
/// subsequent call returns the same error; no retry.
fn bindings() -> Result<&'static WebauthnBindings, &'static str> {
    let result = BINDINGS.get_or_init(|| {
        // LoadLibraryW takes a null-terminated UTF-16 string.
        let dll_name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
            .map_err(|e| format!("LoadLibraryW(webauthn.dll) failed: {e}"))?;

        let add  = get_proc(hmod, b"EXPERIMENTAL_WebAuthNPluginAddAuthenticator\0")?;
        let rem  = get_proc(hmod, b"EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator\0")?;
        let free = get_proc(hmod, b"EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse\0")?;

        Ok(WebauthnBindings {
            add:           unsafe { std::mem::transmute::<_, PfnAdd>(add) },
            remove:        unsafe { std::mem::transmute::<_, PfnRemove>(rem) },
            free_response: unsafe { std::mem::transmute::<_, PfnFreeResponse>(free) },
        })
    });
    result.as_ref().map_err(|s| s.as_str())
}

/// Resolve a symbol from `hmod`, returning a non-null function pointer or a
/// descriptive error. `name` must be a null-terminated ASCII byte literal.
/// The returned pointer type matches windows-rs's `FARPROC` shape
/// (`fn() -> isize`); callers `transmute` it to their real signature.
fn get_proc(hmod: HMODULE, name: &[u8]) -> Result<unsafe extern "system" fn() -> isize, String> {
    // Safety: name is a valid null-terminated C string.
    let proc = unsafe { GetProcAddress(hmod, PCSTR(name.as_ptr())) };
    match proc {
        Some(p) => Ok(p),
        None => {
            // Strip trailing NUL for the error message.
            let name_str = std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("<non-utf8>");
            Err(format!(
                "GetProcAddress({name_str}) returned NULL — webauthn.dll does not export \
                 this EXPERIMENTAL_ symbol. Your Windows build may predate SDK 10.0.26100 \
                 (KB5068861, November 2025)."
            ))
        }
    }
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

/// Call `EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator` with a
/// null-terminated UTF-16 CLSID string.
pub fn remove_authenticator(pwsz_plugin_cls_id: *const u16) -> Result<HRESULT, String> {
    let b = bindings().map_err(|s| s.to_string())?;
    Ok(unsafe { (b.remove)(pwsz_plugin_cls_id) })
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
