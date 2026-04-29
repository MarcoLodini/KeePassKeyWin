//! Operation-signing public key fetch and distribution for the hello handshake.
//!
//! Windows' `webauthn.dll` signs every incoming operation request with an
//! ECDSA P-256 key. The signing public key is obtained once per COM-activated
//! process via `WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)`.
//!
//! This module fetches and caches that key so the sidecar can include it in
//! the `keepasskeywin.hello` params as `opSignPublicKeyB64`. The plugin then
//! uses the key to verify both `pbRequestSignature` (Phase 5.UV.2+) and the
//! UV response signature (Phase 5.UV.4+). The sidecar itself does not perform
//! signature verification — the plugin is the sole verifier (since 5.UV.5).
//!
//! ## Why per-process cache?
//!
//! COM activates us as a fresh EXE process for every operation. The key is
//! owned by the webauthn.dll / Windows Hello infrastructure and is specific
//! to the registered CLSID + caller-package-family pair. Persisting it to
//! HKCU or LocalState would expose it to any same-user process — a trivial
//! privilege-escalation surface: a malicious process could read our key and
//! forge operation requests, bypassing the UV gate entirely.
//!
//! Instead we fetch the key lazily on the first dispatch within this process,
//! cache it in a `OnceLock`, and discard it when the process exits. The
//! cache is fail-closed: a bad key-fetch poisons the `OnceLock` with the
//! error HRESULT, and every subsequent call returns that error permanently
//! without retrying. The fail-closed policy propagates: a `None` from
//! `get_op_sign_pub_key_bytes_for_hello()` causes `handshake()` to return
//! `Err(InvalidRequest)`, the connection is rejected, and no vault dispatch
//! ever reaches the plugin's verifier. This module no longer enforces the
//! gate directly (sidecar-side verification was removed in 5.UV.5); it
//! sources and distributes the key, and the plugin is the sole verifier.
//!
//! **Assumption**: `webauthn.dll` does NOT pool COM server processes across
//! their lifetime. If Microsoft ever changes this model (i.e., one COM EXE
//! handles multiple successive activations), the cached key could become
//! stale. Update the design accordingly at that time.

use std::sync::OnceLock;

// ── HRESULT type ──────────────────────────────────────────────────────────────
//
// On Windows we use the real `windows::core::HRESULT`. On Linux the `windows`
// crate is not a dependency, so we define a compatible newtype that exposes
// the same `.0` field and `is_err()` method, allowing tests to run on Linux.

#[cfg(windows)]
use windows::core::HRESULT;

/// Minimal HRESULT newtype for non-Windows builds. Matches the layout and
/// interface used in this module (`HRESULT(i32)`, `.0` field, `is_err()`).
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HRESULT(pub i32);

#[cfg(not(windows))]
impl HRESULT {
    pub fn is_err(self) -> bool {
        self.0 < 0
    }
}

/// `NTE_BAD_SIGNATURE` (0x80090006) — returned by `get_signing_key_bytes()` on
/// any fetch failure. Used as the cached fail-closed error HRESULT.
pub const NTE_BAD_SIGNATURE: HRESULT = HRESULT(0x8009_0006u32 as i32);

// ── Signing-key cache (process-lifetime, fail-closed) ────────────────────────

/// Process-lifetime cache for the operation-signing public key bytes.
///
/// `Ok(Vec<u8>)` — key successfully fetched; bytes are a `BCRYPT_PUBLIC_KEY_BLOB`.
/// `Err(HRESULT)` — fetch failed; this HRESULT is returned to the caller on
///   every subsequent invocation. The OnceLock is never cleared — fail-closed.
static OP_SIGN_KEY_CACHE: OnceLock<Result<Vec<u8>, HRESULT>> = OnceLock::new();

/// Fetch (and cache) the operation-signing public key for our CLSID.
///
/// On Linux (or any build without the Windows crypto/DLL APIs), the function
/// pointer load fails and `Err(NTE_BAD_SIGNATURE)` is returned and cached.
///
/// On Windows: tries the stable `WebAuthNPluginGetOperationSigningPublicKey`
/// first, then `EXPERIMENTAL2_…`, then `EXPERIMENTAL_…` (PWSTR variant).
/// On success, copies the key bytes into a `Vec<u8>` and frees the runtime's
/// allocation via `WebAuthNPluginFreePublicKeyResponse` (if available).
fn get_signing_key_bytes() -> &'static Result<Vec<u8>, HRESULT> {
    OP_SIGN_KEY_CACHE.get_or_init(|| {
        #[cfg(windows)]
        {
            fetch_key_from_dll()
        }
        #[cfg(not(windows))]
        {
            // Not on Windows — no DLL to call. Fail closed.
            tracing::error!("[sig-verify] not running on Windows; cannot fetch signing key");
            Err(NTE_BAD_SIGNATURE)
        }
    })
}

// ── Windows-only: DLL bindings for key-fetch ─────────────────────────────────

#[cfg(windows)]
mod win_bindings {
    //! Runtime-loaded bindings for `WebAuthNPluginGetOperationSigningPublicKey`
    //! and `WebAuthNPluginFreePublicKeyResponse`.
    //!
    //! Three variants exist across SDK generations (ordered most-to-least stable):
    //!
    //! 1. `WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)` — stable,
    //!    SDK 10.0.26100.6901+, declared in `webauthnplugin.h`.
    //! 2. `EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)` —
    //!    SDK 10.0.26100.6584+, declared in `webauthn.h`. Same signature.
    //! 3. `EXPERIMENTAL_WebAuthNPluginGetOperationSigningPublicKey(PWSTR)` —
    //!    SDK 10.0.26100.6584+. Takes the CLSID as a wide string: uppercase,
    //!    wrapped in braces, e.g. `"{5C6840DC-8BED-4951-9576-B0457FC34E71}"`.
    //!
    //! `WebAuthNPluginFreePublicKeyResponse(PBYTE)` — probed optionally; absent
    //! on some builds (accept the leak, never hard-fail due to its absence).

    use windows::core::{HRESULT, PCSTR, PCWSTR};
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

    use crate::com::types::Guid;

    // ── Function-pointer types ────────────────────────────────────────────

    /// Stable / EXPERIMENTAL2 variant: `(REFCLSID, OUT *DWORD, OUT **BYTE) -> HRESULT`.
    pub type PfnGetKeyRefclsid = unsafe extern "system" fn(
        *const Guid, // REFCLSID
        *mut u32,    // pcbKey (out)
        *mut *mut u8, // ppbKey (out)
    ) -> HRESULT;

    /// EXPERIMENTAL_ (oldest) variant: `(PWSTR, OUT *DWORD, OUT **BYTE) -> HRESULT`.
    pub type PfnGetKeyPwstr = unsafe extern "system" fn(
        *const u16,  // PWSTR (CLSID as wide string)
        *mut u32,    // pcbKey (out)
        *mut *mut u8, // ppbKey (out)
    ) -> HRESULT;

    /// Free the key buffer returned by the Get* functions.
    pub type PfnFreeKey = unsafe extern "system" fn(*mut u8);

    /// Resolved entry points for key-fetch operations.
    pub struct KeyBindings {
        pub get_key: GetKeyVariant,
        pub free_key: Option<PfnFreeKey>,
    }

    pub enum GetKeyVariant {
        RefClsid(PfnGetKeyRefclsid, &'static str),
        Pwstr(PfnGetKeyPwstr),
    }

    unsafe impl Send for KeyBindings {}
    unsafe impl Sync for KeyBindings {}

    /// Load `webauthn.dll` and resolve the key-fetch function pointers.
    /// Tries stable → EXPERIMENTAL2 → EXPERIMENTAL_ in order.
    /// Returns `Err(String)` if none of the three variants are present.
    pub fn load_key_bindings() -> Result<KeyBindings, String> {
        let dll_name: Vec<u16> = "webauthn.dll\0".encode_utf16().collect();
        let hmod: HMODULE = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }
            .map_err(|e| format!("LoadLibraryW(webauthn.dll) failed: {e}"))?;

        let get_key = resolve_get_key(hmod)?;

        // Optional: FreePublicKeyResponse — probe same DLL, accept absence.
        let free_key = probe_free_key(hmod);

        Ok(KeyBindings { get_key, free_key })
    }

    fn resolve_get_key(hmod: HMODULE) -> Result<GetKeyVariant, String> {
        // Try stable name first.
        if let Some(p) = unsafe {
            GetProcAddress(hmod, PCSTR(c"WebAuthNPluginGetOperationSigningPublicKey".as_ptr().cast::<u8>()))
        } {
            let f = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnGetKeyRefclsid>(p)
            };
            tracing::debug!("[sig-verify] resolved: WebAuthNPluginGetOperationSigningPublicKey (stable)");
            return Ok(GetKeyVariant::RefClsid(f, "WebAuthNPluginGetOperationSigningPublicKey"));
        }
        // Try EXPERIMENTAL2 (also REFCLSID).
        if let Some(p) = unsafe {
            GetProcAddress(hmod, PCSTR(c"EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey".as_ptr().cast::<u8>()))
        } {
            let f = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnGetKeyRefclsid>(p)
            };
            tracing::debug!("[sig-verify] resolved: EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey");
            return Ok(GetKeyVariant::RefClsid(f, "EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey"));
        }
        // Try EXPERIMENTAL_ (PWSTR variant).
        if let Some(p) = unsafe {
            GetProcAddress(hmod, PCSTR(c"EXPERIMENTAL_WebAuthNPluginGetOperationSigningPublicKey".as_ptr().cast::<u8>()))
        } {
            let f = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnGetKeyPwstr>(p)
            };
            tracing::debug!("[sig-verify] resolved: EXPERIMENTAL_WebAuthNPluginGetOperationSigningPublicKey (PWSTR)");
            return Ok(GetKeyVariant::Pwstr(f));
        }
        Err(
            "GetProcAddress failed for WebAuthNPluginGetOperationSigningPublicKey, \
             EXPERIMENTAL2_… and EXPERIMENTAL_… — \
             webauthn.dll on this build does not export any of them. \
             Requires Win11 24H2 26100.6725+ (KB5068861, Nov 2025).".to_string()
        )
    }

    fn probe_free_key(hmod: HMODULE) -> Option<PfnFreeKey> {
        unsafe {
            GetProcAddress(hmod, PCSTR(c"WebAuthNPluginFreePublicKeyResponse".as_ptr().cast::<u8>()))
        }.map(|p| unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnFreeKey>(p)
        })
    }
}

// ── Windows-only: actual key fetch from DLL ───────────────────────────────────

#[cfg(windows)]
fn fetch_key_from_dll() -> Result<Vec<u8>, HRESULT> {
    use win_bindings::{GetKeyVariant, load_key_bindings};
    use crate::com::exe_server::CLSID_GUID;

    let bindings = load_key_bindings().map_err(|e| {
        tracing::error!("[sig-verify] key-fetch DLL load failed: {e}");
        NTE_BAD_SIGNATURE
    })?;

    let mut cb_key: u32 = 0;
    let mut pb_key: *mut u8 = std::ptr::null_mut();

    let hr = match &bindings.get_key {
        GetKeyVariant::RefClsid(f, sym) => {
            tracing::debug!("[sig-verify] calling {sym}(REFCLSID)");
            unsafe { f(&CLSID_GUID as *const _, &mut cb_key, &mut pb_key) }
        }
        GetKeyVariant::Pwstr(f) => {
            // Format CLSID as uppercase with braces:
            // "{5C6840DC-8BED-4951-9576-B0457FC34E71}"
            let g = &CLSID_GUID;
            let s = format!(
                "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                g.data1, g.data2, g.data3,
                g.data4[0], g.data4[1],
                g.data4[2], g.data4[3], g.data4[4],
                g.data4[5], g.data4[6], g.data4[7],
            );
            tracing::debug!("[sig-verify] calling EXPERIMENTAL_(PWSTR) clsid_str={s}");
            let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { f(wide.as_ptr(), &mut cb_key, &mut pb_key) }
        }
    };

    if hr.is_err() {
        tracing::error!("[sig-verify] GetOperationSigningPublicKey failed: 0x{:08x}", hr.0 as u32);
        // Free if the function allocated anyway (defensive).
        if !pb_key.is_null() {
            if let Some(free_f) = bindings.free_key {
                unsafe { free_f(pb_key) };
            }
        }
        return Err(NTE_BAD_SIGNATURE);
    }

    if pb_key.is_null() || cb_key == 0 {
        tracing::error!("[sig-verify] GetOperationSigningPublicKey returned null/empty key (hr=S_OK)");
        return Err(NTE_BAD_SIGNATURE);
    }

    // Copy out before freeing.
    let key_bytes = unsafe { std::slice::from_raw_parts(pb_key, cb_key as usize) }.to_vec();

    // Free the DLL-allocated buffer.
    match bindings.free_key {
        Some(free_f) => unsafe { free_f(pb_key) },
        None => {
            // Symbol absent — accept the leak. Log at debug level to avoid noise.
            tracing::debug!("[sig-verify] WebAuthNPluginFreePublicKeyResponse not found; key buffer leaked ({}B)", cb_key);
        }
    }

    tracing::debug!("[sig-verify] signing key fetched: {}B", key_bytes.len());
    Ok(key_bytes)
}

// ── Crate-internal helper for hello-params key distribution ─────────────────

/// Returns the operation-signing public key bytes for inclusion in the
/// `keepasskeywin.hello` params as `opSignPublicKeyB64`.
///
/// Returns `Some(bytes)` when the key fetch succeeds. Returns `None` on any
/// error; since 5.UV.4 the caller (`PipeClient::handshake`) propagates `None`
/// as `Err(InvalidRequest)` and the connection fails — the plugin requires
/// `opSignPublicKeyB64` in hello and rejects requests without a cached pubkey.
pub fn get_op_sign_pub_key_bytes_for_hello() -> Option<Vec<u8>> {
    match get_signing_key_bytes() {
        Ok(bytes) => Some(bytes.clone()),
        Err(hr) => {
            tracing::warn!(
                "[sig-verify] op-sign key unavailable for hello params (hr=0x{:08x}); \
                 handshake will fail (5.UV.4 requires opSignPublicKeyB64)",
                hr.0 as u32
            );
            None
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The OnceLock cache is poisoned on the first failed key-fetch and every
    /// subsequent call sees the same cached error without re-attempting the fetch.
    ///
    /// On Linux we can confirm this directly: the first call to
    /// `get_signing_key_bytes()` fails (no DLL), and the second call returns
    /// the same `Err` from the same static allocation.
    #[test]
    fn key_cache_fail_closed() {
        // Note: OP_SIGN_KEY_CACHE is a process-global OnceLock. Other tests
        // in this module may have already populated it. That's intentional —
        // once set, it cannot change. We just confirm it is Err if we're on
        // Linux, or that it is consistent (Err same pointer) if already set.
        let first = get_signing_key_bytes();
        let second = get_signing_key_bytes();

        // On Windows the key might be Ok — just confirm consistent.
        // On Linux it must be Err.
        match (first, second) {
            (Ok(_), Ok(_)) => {
                // Windows with real DLL — cache populated successfully.
                // The same Vec<u8> is returned both times (same OnceLock slot).
            }
            (Err(a), Err(b)) => {
                // Cached error — confirm same HRESULT value (fail-closed).
                assert_eq!(a.0, b.0, "cached error HRESULT must be stable");
                // Also confirm same static-string pointer level: the OnceLock
                // holds a single allocation so both references point into it.
                assert!(std::ptr::eq(a as *const _, b as *const _),
                    "both calls must return a reference to the SAME OnceLock slot");
            }
            _ => panic!("OnceLock result must be stable across calls"),
        }
    }

    // ── SHA-256 helper pin (Phase 5.UV.3) ─────────────────────────────────────

    /// Pin the SHA-256 algorithm used in `dispatch_operation` to produce
    /// `buffer_to_sign` for `perform_user_verification_2`.
    ///
    /// The sidecar computes `SHA-256(pbEncodedRequest)` and passes the 32-byte
    /// digest as `pb_buffer_to_sign` to the v2 UV entrypoint. The plugin
    /// re-derives the same digest in 5.UV.4 to verify the UV response.
    /// Both sides MUST agree on the algorithm — this test makes that contract
    /// explicit and regression-proof.
    ///
    /// Expected output from NIST FIPS 180-4 / RFC 6234 §1 test vector:
    ///   SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #[test]
    fn sha256_of_abc_matches_known_vector() {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(b"abc");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256(b\"abc\") must match the NIST FIPS 180-4 known vector"
        );
    }
}
