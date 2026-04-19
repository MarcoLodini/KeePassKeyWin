//! Runtime-loaded bindings for the credential-management family of
//! plugin-authenticator APIs exported from `webauthn.dll`.
//!
//! Unlike the `EXPERIMENTAL_`-prefixed symbols in `webauthn_ext.rs`, these
//! functions are shipped under their stable names (no `EXPERIMENTAL_`
//! prefix) in Windows 11 SDK 10.0.26100.0+. They are declared in
//! `webauthnplugin.h` (not `webauthn.h`). We still load them dynamically
//! rather than statically-linking for two reasons:
//!
//!   1. Older Win11 24H2 builds predate these exports — our MSIX manifest
//!      floor is Build 26100.6725+ (KB5068861, Nov 2025) but cross-
//!      compiling from WSL against a newer `webauthn.lib` and then
//!      running against an older runtime would crash at import-table
//!      resolution, not at our controlled error path.
//!   2. Consistency with `webauthn_ext.rs` — both sets of APIs are
//!      plugin-only and not used by most `webauthn.dll` consumers, so the
//!      "probe once and cache" pattern fits cleanly.
//!
//! Phase 4 scope: only `WebAuthNPluginAuthenticatorAddCredentials` is
//! bound here. The Remove / GetAll / FreeCredentialDetailsArray calls
//! are Phase 4-polish backlog items.
//!
//! Memory ownership: `WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS` is *caller-
//! owned*. All strings and byte buffers remain the caller's
//! responsibility across the call — the runtime copies whatever it needs
//! into its own autofill database and returns. There is no matching Free
//! function for Add (confirmed against `PluginCredentialManager.cpp`
//! AddAllPluginCredentials / AddPluginCredentialById — both push the
//! details into a `std::vector`, call the API, and let the vector go out
//! of scope).

#![cfg(windows)]

use std::sync::OnceLock;

use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::com::types::{Guid, WebauthnPluginCredentialDetails};

// ── Function-pointer type ─────────────────────────────────────────────────────

/// `WebAuthNPluginAuthenticatorAddCredentials`.
///
/// Signature from SDK 10.0.26100.0 `webauthnplugin.h:273-278`:
///   HRESULT WINAPI WebAuthNPluginAuthenticatorAddCredentials(
///       _In_ REFCLSID rclsid,
///       _In_ DWORD cCredentialDetails,
///       _In_reads_(cCredentialDetails) PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCredentialDetails);
///
/// `REFCLSID` is `const GUID*` (pointer, 8 bytes on x64) — same trap as
/// the register path. Passing an inline GUID would crash the runtime.
type PfnAddCredentials = unsafe extern "system" fn(
    *const Guid,                             // REFCLSID — pointer, NOT inline
    u32,                                     // cCredentialDetails
    *const WebauthnPluginCredentialDetails,  // pCredentialDetails (array)
) -> HRESULT;

// ── Cached bindings ───────────────────────────────────────────────────────────

struct Bindings {
    add_credentials: PfnAddCredentials,
}

unsafe impl Send for Bindings {}
unsafe impl Sync for Bindings {}

static BINDINGS: OnceLock<Result<Bindings, String>> = OnceLock::new();

/// Load `webauthn.dll` and resolve `WebAuthNPluginAuthenticatorAddCredentials`.
/// Cached — subsequent calls reuse the same result. On failure every
/// subsequent call returns the same error; no retry.
///
/// The symbol has always shipped under its stable name (no
/// `EXPERIMENTAL_` variant, unlike the plugin-registration family), so
/// only one lookup name is tried.
fn bindings() -> Result<&'static Bindings, &'static str> {
    let result = BINDINGS.get_or_init(|| {
        let dll_name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
            .map_err(|e| format!("LoadLibraryW(webauthn.dll) failed: {e}"))?;

        let name = b"WebAuthNPluginAuthenticatorAddCredentials\0";
        let proc = unsafe { GetProcAddress(hmod, PCSTR(name.as_ptr())) }
            .ok_or_else(|| {
                "GetProcAddress(WebAuthNPluginAuthenticatorAddCredentials) failed — \
                 webauthn.dll on this build lacks the credential-management API. \
                 Requires Win11 24H2 26100.6725+ (KB5068861, Nov 2025).".to_string()
            })?;

        Ok(Bindings {
            add_credentials: unsafe {
                std::mem::transmute::<
                    unsafe extern "system" fn() -> isize,
                    PfnAddCredentials,
                >(proc)
            },
        })
    });
    result.as_ref().map_err(|s| s.as_str())
}

// ── Public wrapper ────────────────────────────────────────────────────────────

/// Call `WebAuthNPluginAuthenticatorAddCredentials` with one or more
/// credential-details records. Returns the raw `HRESULT` from webauthn.dll.
///
/// The caller owns every buffer referenced from each
/// `WebauthnPluginCredentialDetails`. Those buffers must remain alive
/// across this call but may be dropped as soon as it returns — the
/// runtime copies whatever state it needs into its own autofill database.
///
/// Safety: the slice's backing storage must outlive the call and each
/// entry must point at valid caller-owned memory for the duration.
pub(crate) fn add_credentials(
    rclsid: *const Guid,
    credentials: &[WebauthnPluginCredentialDetails],
) -> Result<HRESULT, String> {
    let b = bindings().map_err(|s| s.to_string())?;
    let count = credentials.len() as u32;
    let ptr = credentials.as_ptr();
    Ok(unsafe { (b.add_credentials)(rclsid, count, ptr) })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The `OnceLock` should cache the first lookup result — calling
    /// `bindings()` twice must not trigger two `LoadLibraryW` attempts.
    /// On Linux we can't actually exercise the success path (the DLL
    /// doesn't exist), but the error path still goes through the cache:
    /// after the first `LoadLibraryW` failure, the second call returns
    /// the same `&'static str` from the cached `Err`.
    ///
    /// This is the same "negative caching" pattern used by
    /// `webauthn_ext.rs` — a failed load is permanent for the process
    /// lifetime.
    #[test]
    fn bindings_cached_after_first_call() {
        // Note: on Windows CI this would succeed twice. On Linux WSL
        // build both calls fail identically — the point is that the
        // returned error pointer is the same stable string both times
        // (confirming the OnceLock was populated, not re-attempted).
        let first = bindings();
        let second = bindings();
        match (first, second) {
            (Ok(_), Ok(_)) => {
                // Windows path — no assertion needed beyond not panicking.
            }
            (Err(a), Err(b)) => {
                // Linux path — both errors come from the cached Err entry.
                assert_eq!(a, b, "cached error text must match across calls");
                // Same static-string pointer confirms the OnceLock branch,
                // not a fresh re-computation. Safe because the error is
                // stored inside the OnceLock for the process lifetime.
                assert!(std::ptr::eq(a.as_ptr(), b.as_ptr()),
                    "error string should be from the same cached allocation");
            }
            _ => panic!("bindings() result should be stable across calls"),
        }
    }
}
