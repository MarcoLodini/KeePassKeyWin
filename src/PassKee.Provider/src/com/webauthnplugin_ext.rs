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
//! All four credential-management functions share the same `OnceLock`-cached
//! `Bindings` struct and single `LoadLibraryW` call.
//!
//! Memory ownership:
//!   - Add / Remove: caller-owned buffers. The runtime copies what it needs
//!     and returns; no matching Free for these two.
//!   - GetAll: runtime allocates both the outer array and all inner string /
//!     byte buffers. `FreeCredentialDetailsArray` must be called to release
//!     the runtime's allocation; every inner pointer is valid until that call.
//!
//! Signatures confirmed against `webauthnplugin.h` from Windows SDK
//! 10.0.26100.7175 (Microsoft.Windows.SDK.CPP NuGet package,
//! path `c/Include/10.0.26100.0/um/webauthnplugin.h`).

#![cfg(windows)]

use std::sync::OnceLock;

use windows::core::{HRESULT, PCSTR, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

use crate::com::types::{Guid, WebauthnPluginCredentialDetails};

// ── Function-pointer types ────────────────────────────────────────────────────

/// `WebAuthNPluginAuthenticatorAddCredentials`.
///
/// From SDK `webauthnplugin.h`:
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

/// `WebAuthNPluginAuthenticatorGetAllCredentials`.
///
/// From SDK `webauthnplugin.h`:
///   HRESULT WINAPI WebAuthNPluginAuthenticatorGetAllCredentials(
///       _In_ REFCLSID rclsid,
///       _Out_ DWORD* pcCredentialDetails,
///       _Outptr_result_buffer_maybenull_(*pcCredentialDetails)
///           PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS* ppCredentialDetailsArray);
///
/// On S_OK the runtime allocates both the outer array and the inner
/// string/byte buffers. The caller must call `FreeCredentialDetailsArray`
/// when done — every inner pointer is valid until that call.
/// On S_OK with zero credentials `*ppCredentialDetailsArray` may be null.
type PfnGetAllCredentials = unsafe extern "system" fn(
    *const Guid,                              // REFCLSID — pointer
    *mut u32,                                 // pcCredentialDetails (out)
    *mut *mut WebauthnPluginCredentialDetails, // ppCredentialDetailsArray (out)
) -> HRESULT;

/// `WebAuthNPluginAuthenticatorRemoveCredentials`.
///
/// From SDK `webauthnplugin.h`:
///   HRESULT WINAPI WebAuthNPluginAuthenticatorRemoveCredentials(
///       _In_ REFCLSID rclsid,
///       _In_ DWORD cCredentialDetails,
///       _In_reads_(cCredentialDetails) PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCredentialDetails);
///
/// Mirrors `AddCredentials` — caller-owned const pointer. The runtime copies
/// what it needs; caller retains ownership of the buffers.
type PfnRemoveCredentials = unsafe extern "system" fn(
    *const Guid,                             // REFCLSID — pointer
    u32,                                     // cCredentialDetails
    *const WebauthnPluginCredentialDetails,  // pCredentialDetails (array)
) -> HRESULT;

/// `WebAuthNPluginAuthenticatorFreeCredentialDetailsArray`.
///
/// From SDK `webauthnplugin.h`:
///   void WINAPI WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(
///       _In_ DWORD cCredentialDetails,
///       _In_reads_(cCredentialDetails) PWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCredentialDetailsArray);
///
/// Returns void. No REFCLSID. Takes a non-const (mutable) pointer.
/// Frees both the outer array and all inner string/byte buffers allocated
/// by `GetAllCredentials`. Must be called exactly once after the array is
/// no longer needed; all inner pointers become invalid after this call.
type PfnFreeCredentialDetailsArray = unsafe extern "system" fn(
    u32,                                     // cCredentialDetails
    *mut WebauthnPluginCredentialDetails,    // pCredentialDetailsArray (non-const)
);

// ── Cached bindings ───────────────────────────────────────────────────────────

struct Bindings {
    add_credentials:              PfnAddCredentials,
    get_all_credentials:          PfnGetAllCredentials,
    remove_credentials:           PfnRemoveCredentials,
    free_credential_details_array: PfnFreeCredentialDetailsArray,
}

unsafe impl Send for Bindings {}
unsafe impl Sync for Bindings {}

static BINDINGS: OnceLock<Result<Bindings, String>> = OnceLock::new();

/// Load `webauthn.dll` and resolve all four credential-management functions.
/// Cached — subsequent calls reuse the same result. On failure every
/// subsequent call returns the same error; no retry.
///
/// All symbols ship under their stable names (no `EXPERIMENTAL_` variant,
/// unlike the plugin-registration family).
fn bindings() -> Result<&'static Bindings, &'static str> {
    let result = BINDINGS.get_or_init(|| {
        let dll_name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
            .map_err(|e| format!("LoadLibraryW(webauthn.dll) failed: {e}"))?;

        macro_rules! resolve {
            ($name:literal, $ty:ty) => {{
                let proc = unsafe { GetProcAddress(hmod, PCSTR($name.as_ptr())) }
                    .ok_or_else(|| {
                        format!(
                            "GetProcAddress({}) failed — \
                             webauthn.dll on this build lacks the credential-management API. \
                             Requires Win11 24H2 26100.6725+ (KB5068861, Nov 2025).",
                            std::str::from_utf8(&$name[..$name.len() - 1]).unwrap_or("?")
                        )
                    })?;
                unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(proc)
                }
            }};
        }

        Ok(Bindings {
            add_credentials: resolve!(
                b"WebAuthNPluginAuthenticatorAddCredentials\0",
                PfnAddCredentials
            ),
            get_all_credentials: resolve!(
                b"WebAuthNPluginAuthenticatorGetAllCredentials\0",
                PfnGetAllCredentials
            ),
            remove_credentials: resolve!(
                b"WebAuthNPluginAuthenticatorRemoveCredentials\0",
                PfnRemoveCredentials
            ),
            free_credential_details_array: resolve!(
                b"WebAuthNPluginAuthenticatorFreeCredentialDetailsArray\0",
                PfnFreeCredentialDetailsArray
            ),
        })
    });
    result.as_ref().map_err(|s| s.as_str())
}

// ── Public wrappers ───────────────────────────────────────────────────────────

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

/// Call `WebAuthNPluginAuthenticatorGetAllCredentials`.
///
/// On success returns `(count, array_ptr)`. The runtime allocates both the
/// outer array and all inner string/byte buffers; call
/// `free_credential_details_array(count, array_ptr)` when done. All inner
/// pointers are valid until that call. `array_ptr` may be null when
/// `count == 0`.
pub(crate) fn get_all_credentials(
    rclsid: *const Guid,
) -> Result<(u32, *mut WebauthnPluginCredentialDetails), String> {
    let b = bindings().map_err(|s| s.to_string())?;
    let mut count: u32 = 0;
    let mut arr: *mut WebauthnPluginCredentialDetails = std::ptr::null_mut();
    let hr = unsafe { (b.get_all_credentials)(rclsid, &mut count, &mut arr) };
    if hr.is_err() {
        return Err(format!("GetAllCredentials failed: 0x{:08x}", hr.0 as u32));
    }
    Ok((count, arr))
}

/// Call `WebAuthNPluginAuthenticatorRemoveCredentials` for a single entry.
///
/// `detail` must point at a single `WebauthnPluginCredentialDetails`.
/// The caller owns the record and its buffers; the runtime copies what
/// it needs. `rclsid` must be a pointer (`REFCLSID`), not inline bytes.
pub(crate) fn remove_credentials(
    rclsid: *const Guid,
    detail: *const WebauthnPluginCredentialDetails,
) -> Result<HRESULT, String> {
    let b = bindings().map_err(|s| s.to_string())?;
    Ok(unsafe { (b.remove_credentials)(rclsid, 1, detail) })
}

/// Call `WebAuthNPluginAuthenticatorFreeCredentialDetailsArray`.
///
/// Frees the outer array and all inner string/byte buffers that
/// `GetAllCredentials` allocated. Every inner pointer in the array
/// becomes invalid after this call. No-ops when `arr` is null or
/// `count == 0`.
///
/// # Safety
/// `arr` must be the pointer returned by a successful `GetAllCredentials`
/// call, and `count` must match the count returned by that call.
pub(crate) fn free_credential_details_array(
    count: u32,
    arr: *mut WebauthnPluginCredentialDetails,
) {
    if count == 0 || arr.is_null() {
        return;
    }
    // Bindings may not be available (e.g. on Linux or old builds); if so,
    // there is nothing to free (GetAllCredentials would also have failed).
    if let Ok(b) = bindings() {
        unsafe { (b.free_credential_details_array)(count, arr) };
    }
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

    /// The three new public wrappers all go through the same `OnceLock`.
    /// On Linux they return the same cached error as `add_credentials`.
    /// This confirms the OnceLock is shared (not four separate loads).
    #[test]
    fn new_wrappers_share_cached_bindings() {
        use std::ptr;

        // Warm the cache via bindings().
        let cached = bindings();

        // add_credentials
        let r_add = add_credentials(ptr::null(), &[]);
        // get_all_credentials
        let r_get = get_all_credentials(ptr::null());
        // remove_credentials (null detail; FFI not reached on Linux)
        let r_rem = remove_credentials(ptr::null(), ptr::null());

        match cached {
            Ok(_) => {
                // Windows path: wrappers succeed or fail with an HRESULT, but
                // they must not panic (bindings resolved).
                let _ = (r_add, r_get, r_rem);
            }
            Err(cached_err) => {
                // Linux path: all three wrappers must return the same cached
                // error string (same OnceLock, same static allocation).
                for (label, result) in [
                    ("add_credentials",    r_add.map(|_| ())),
                    ("get_all_credentials", r_get.map(|_| ())),
                    ("remove_credentials", r_rem.map(|_| ())),
                ] {
                    match result {
                        Ok(()) => panic!("{label} succeeded on Linux — unexpected"),
                        Err(ref msg) => assert_eq!(
                            msg.as_str(), cached_err,
                            "{label}: error should match cached bindings error"
                        ),
                    }
                }
            }
        }
    }

    /// `free_credential_details_array` is infallible and must not panic
    /// when bindings are unavailable (Linux). Calling it here exercises
    /// the early-return guard on the Linux path.
    #[test]
    fn free_credential_details_array_noop_on_no_bindings() {
        // On Linux bindings() fails, so free is a no-op. On Windows the
        // DLL is present and count=0 / null array is a valid no-op call.
        // Either way: must not panic.
        free_credential_details_array(0, std::ptr::null_mut());
    }
}
