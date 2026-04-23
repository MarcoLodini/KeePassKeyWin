//! Request-signature verification for `WEBAUTHN_PLUGIN_OPERATION_REQUEST`
//! and `WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST`.
//!
//! Windows' `webauthn.dll` signs every incoming operation request with an
//! ECDSA P-256 key. The signing public key is obtained once per COM-activated
//! process via `WebAuthNPluginGetOperationSigningPublicKey(REFCLSID)`.
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
//! without retrying. This is intentional: if the key-fetch fails we have
//! no verifiable basis for trusting requests and should reject them all.
//!
//! **Assumption**: `webauthn.dll` does NOT pool COM server processes across
//! their lifetime. If Microsoft ever changes this model (i.e., one COM EXE
//! handles multiple successive activations), the cached key could become
//! stale. Update the design accordingly at that time.
//!
//! ## Bypass env var
//!
//! Setting `KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY=1` is an all-or-nothing
//! escape hatch. When set, the entire verification pathway is skipped —
//! including the key-fetch. Returns `S_OK` unconditionally. A single
//! prominent `tracing::warn!` is emitted when the bypass is active.
//! **Do not enable in production.**
//!
//! ## Verification API (Microsoft PasskeyManager sample)
//!
//! ```text
//! NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);
//! NCryptImportKey(hProvider, NULL, BCRYPT_PUBLIC_KEY_BLOB, nullptr,
//!                 &hKey, pbKeyData, cbKeyData, 0);
//! BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, ...);
//! BCryptHashData(..., pbEncodedRequest, cbEncodedRequest, 0);
//! BCryptFinishHash(..., digest, 32, 0);
//! NCryptVerifySignature(hKey, nullptr, digest, 32, pbSig, cbSig, 0);
//! ```
//!
//! Key points:
//! - Blob type is `BCRYPT_PUBLIC_KEY_BLOB` (generic); NCrypt dispatches on
//!   the embedded magic (`BCRYPT_ECDSA_P256_MAGIC` for our key).
//! - Signed payload is the raw CBOR bytes of `pbEncodedRequest` — no
//!   concatenation, no preamble, no trailer.
//! - SHA-256 is computed by the caller; `NCryptVerifySignature` does NOT
//!   hash internally.
//! - ECDSA P-256: padding info is `NULL`, flags is `0`.

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

/// `NTE_BAD_SIGNATURE` (0x80090006) — returned on any verification failure.
pub const NTE_BAD_SIGNATURE: HRESULT = HRESULT(0x8009_0006u32 as i32);

/// `S_OK` (0x00000000) — returned on successful verification or bypass.
const S_OK: HRESULT = HRESULT(0);

// ── Env-var bypass ────────────────────────────────────────────────────────────

/// Returns `true` if the bypass env var is set (value `"1"`, `"true"`, or
/// `"yes"`, case-insensitive). When `true`, `verify_request_signature`
/// returns `S_OK` immediately, skipping both the key-fetch and verification.
fn is_bypass_enabled() -> bool {
    match std::env::var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY") {
        Ok(v) => matches!(v.to_ascii_lowercase().trim(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

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
            GetProcAddress(hmod, PCSTR(b"WebAuthNPluginGetOperationSigningPublicKey\0".as_ptr()))
        } {
            let f = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnGetKeyRefclsid>(p)
            };
            tracing::debug!("[sig-verify] resolved: WebAuthNPluginGetOperationSigningPublicKey (stable)");
            return Ok(GetKeyVariant::RefClsid(f, "WebAuthNPluginGetOperationSigningPublicKey"));
        }
        // Try EXPERIMENTAL2 (also REFCLSID).
        if let Some(p) = unsafe {
            GetProcAddress(hmod, PCSTR(b"EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey\0".as_ptr()))
        } {
            let f = unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, PfnGetKeyRefclsid>(p)
            };
            tracing::debug!("[sig-verify] resolved: EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey");
            return Ok(GetKeyVariant::RefClsid(f, "EXPERIMENTAL2_WebAuthNPluginGetOperationSigningPublicKey"));
        }
        // Try EXPERIMENTAL_ (PWSTR variant).
        if let Some(p) = unsafe {
            GetProcAddress(hmod, PCSTR(b"EXPERIMENTAL_WebAuthNPluginGetOperationSigningPublicKey\0".as_ptr()))
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
            GetProcAddress(hmod, PCSTR(b"WebAuthNPluginFreePublicKeyResponse\0".as_ptr()))
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

// ── Windows-only: NCrypt + BCrypt verification ────────────────────────────────

#[cfg(windows)]
fn verify_with_ncrypt(
    key_bytes: &[u8],
    pb_sig: &[u8],
    pb_encoded: &[u8],
) -> HRESULT {
    use windows::Win32::Security::Cryptography::{
        BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData,
        NCryptFreeObject, NCryptImportKey, NCryptOpenStorageProvider,
        NCryptVerifySignature,
        BCRYPT_HASH_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_HANDLE,
        NCRYPT_PROV_HANDLE,
        BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_SHA256_ALG_HANDLE,
        MS_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS,
    };

    // ── 1. Open NCrypt storage provider ──────────────────────────────────
    let mut h_prov = NCRYPT_PROV_HANDLE::default();
    if let Err(e) = unsafe { NCryptOpenStorageProvider(&mut h_prov, MS_KEY_STORAGE_PROVIDER, 0) } {
        tracing::error!("[sig-verify] NCryptOpenStorageProvider failed: {e}");
        return NTE_BAD_SIGNATURE;
    }
    // RAII helper: free h_prov on every exit path.
    // SAFETY: we call NCryptFreeObject exactly once per handle (not moved into ncrypt_free).
    let free_prov = || unsafe { let _ = NCryptFreeObject(NCRYPT_HANDLE::from(h_prov)); };

    // ── 2. Import the public key blob ─────────────────────────────────────
    // blob_type is BCRYPT_PUBLIC_KEY_BLOB ("PUBLICBLOB") — NCrypt dispatches on the
    // embedded magic (BCRYPT_ECDSA_P256_MAGIC for our P-256 key).
    // himportkey = None (NULL) — we are not wrapping with another key.
    // pParameterList = None (NULL) — no additional parameters needed.
    let mut h_key = NCRYPT_KEY_HANDLE::default();
    if let Err(e) = unsafe {
        NCryptImportKey(
            h_prov,
            None,               // hImportKey = NULL
            BCRYPT_PUBLIC_KEY_BLOB,
            None,               // pParameterList = NULL
            &mut h_key,
            key_bytes,
            NCRYPT_FLAGS(0),
        )
    } {
        tracing::error!("[sig-verify] NCryptImportKey failed: {e}");
        free_prov();
        return NTE_BAD_SIGNATURE;
    }
    let free_key_and_prov = || unsafe {
        let _ = NCryptFreeObject(NCRYPT_HANDLE::from(h_key));
        let _ = NCryptFreeObject(NCRYPT_HANDLE::from(h_prov));
    };

    // ── 3. Hash the encoded-request bytes with SHA-256 ────────────────────
    // Use BCRYPT_SHA256_ALG_HANDLE — a pre-opened algorithm handle provided
    // by the BCrypt API, no BCryptOpenAlgorithmProvider call needed.
    let mut h_hash = BCRYPT_HASH_HANDLE::default();
    if unsafe { BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut h_hash, None, None, 0) }.is_err() {
        tracing::error!("[sig-verify] BCryptCreateHash failed");
        free_key_and_prov();
        return NTE_BAD_SIGNATURE;
    }

    if unsafe { BCryptHashData(h_hash, pb_encoded, 0) }.is_err() {
        tracing::error!("[sig-verify] BCryptHashData failed");
        unsafe { let _ = BCryptDestroyHash(h_hash); };
        free_key_and_prov();
        return NTE_BAD_SIGNATURE;
    }

    let mut digest = [0u8; 32];
    let finish_ok = unsafe { BCryptFinishHash(h_hash, &mut digest, 0) }.is_ok();
    unsafe { let _ = BCryptDestroyHash(h_hash); };

    if !finish_ok {
        tracing::error!("[sig-verify] BCryptFinishHash failed");
        free_key_and_prov();
        return NTE_BAD_SIGNATURE;
    }

    // ── 4. Verify ECDSA P-256 signature ───────────────────────────────────
    // paddingInfo = None (NULL), flags = 0 — correct for ECDSA P-256.
    let verify_result = unsafe {
        NCryptVerifySignature(
            h_key,
            None,           // pPaddingInfo = NULL (ECDSA)
            &digest,
            pb_sig,
            NCRYPT_FLAGS(0),
        )
    };

    free_key_and_prov();

    if verify_result.is_err() {
        tracing::warn!("[sig-verify] NCryptVerifySignature FAILED: {}", verify_result.unwrap_err());
        NTE_BAD_SIGNATURE
    } else {
        tracing::debug!("[sig-verify] NCryptVerifySignature OK");
        S_OK
    }
}

// ── Crate-internal helper for hello-params key distribution ─────────────────

/// Returns the operation-signing public key bytes for inclusion in the
/// `keepasskeywin.hello` params as `opSignPublicKeyB64` (Phase 5.UV.1).
///
/// Returns `Some(bytes)` when the key has already been fetched (or can be
/// fetched now successfully). Returns `None` on any error — the caller should
/// log a `warn!` and send hello without the field for backward-compat
/// (the plugin treats the field as optional in 5.UV.1).
pub(crate) fn get_op_sign_pub_key_bytes_for_hello() -> Option<Vec<u8>> {
    match get_signing_key_bytes() {
        Ok(bytes) => Some(bytes.clone()),
        Err(hr) => {
            tracing::warn!(
                "[sig-verify] op-sign key unavailable for hello params (hr=0x{:08x}); \
                 sidecar will send hello without opSignPublicKeyB64",
                hr.0 as u32
            );
            None
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Verify the `pbRequestSignature` field of an operation request against the
/// Windows op-signing public key.
///
/// - `pb_sig`: the signature bytes from the request struct.
/// - `pb_encoded`: the raw CBOR bytes of the encoded request (the signed payload).
///
/// Returns `S_OK` (0) on success, `NTE_BAD_SIGNATURE` (0x80090006) on any
/// failure (key-fetch error, hash error, signature mismatch, empty inputs).
///
/// If the bypass env var `KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY=1` is set,
/// the entire verification pathway is skipped and `S_OK` is returned.
pub fn verify_request_signature(pb_sig: &[u8], pb_encoded: &[u8]) -> HRESULT {
    // Env-var bypass — all-or-nothing, including key-fetch.
    if is_bypass_enabled() {
        tracing::warn!(
            "[sig-verify] BYPASS ENABLED via env var — request signature verification is OFF; \
             do not run in production"
        );
        return S_OK;
    }

    // Reject obviously-bad inputs before touching crypto.
    if pb_sig.is_empty() || pb_encoded.is_empty() {
        tracing::warn!("[sig-verify] REJECT: empty signature or encoded request");
        return NTE_BAD_SIGNATURE;
    }

    // Fetch (or retrieve from cache) the signing key.
    let key_bytes = match get_signing_key_bytes() {
        Ok(k) => k.as_slice(),
        Err(hr) => {
            tracing::error!("[sig-verify] REJECT: key-fetch failed (cached hr=0x{:08x})", hr.0 as u32);
            return NTE_BAD_SIGNATURE;
        }
    };

    // Perform NCrypt/BCrypt verification.
    #[cfg(windows)]
    {
        verify_with_ncrypt(key_bytes, pb_sig, pb_encoded)
    }
    #[cfg(not(windows))]
    {
        // On Linux this branch is unreachable because get_signing_key_bytes()
        // always returns Err on non-Windows, which returns early above.
        // Keep a dummy reference to suppress the unused-variable warning.
        let _ = key_bytes;
        NTE_BAD_SIGNATURE
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The bypass env var causes `verify_request_signature` to return S_OK
    /// without touching key-fetch or crypto — even with garbage inputs.
    #[test]
    fn bypass_env_var_returns_s_ok() {
        // Set the bypass env var for this test.
        // SAFETY: single-threaded test; env mutation is test-local.
        // We restore the previous value afterwards so other tests are not affected.
        let prev = std::env::var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY").ok();
        std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", "1");

        let result = verify_request_signature(b"bad-sig", b"bad-encoded");

        // Restore env.
        match prev {
            Some(v) => std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", v),
            None => std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY"),
        }

        assert_eq!(result, S_OK, "bypass must return S_OK regardless of inputs");
    }

    /// `verify_request_signature` with empty signature returns `NTE_BAD_SIGNATURE`.
    /// Does not require the bypass; tests the early-return guard.
    #[test]
    fn empty_signature_returns_nte_bad_signature() {
        // Ensure bypass is OFF for this test.
        let prev = std::env::var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY").ok();
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");

        let result = verify_request_signature(b"", b"some-encoded-request");

        match prev {
            Some(v) => std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", v),
            None => std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY"),
        }

        assert_eq!(result, NTE_BAD_SIGNATURE, "empty signature must be rejected");
    }

    /// `verify_request_signature` with empty encoded request returns `NTE_BAD_SIGNATURE`.
    #[test]
    fn empty_encoded_request_returns_nte_bad_signature() {
        let prev = std::env::var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY").ok();
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");

        let result = verify_request_signature(b"some-sig", b"");

        match prev {
            Some(v) => std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", v),
            None => std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY"),
        }

        assert_eq!(result, NTE_BAD_SIGNATURE, "empty encoded request must be rejected");
    }

    /// On Linux (or any environment where the DLL load fails), key-fetch will
    /// fail, causing `verify_request_signature` to return `NTE_BAD_SIGNATURE`.
    /// This also validates the fail-closed semantics of the OnceLock cache.
    ///
    /// On Windows with the real webauthn.dll, `verify_request_signature` with
    /// a plausible-length signature and CBOR blob STILL returns NTE_BAD_SIGNATURE
    /// (because the signature is forged). Either way, NTE_BAD_SIGNATURE is the
    /// expected result for inputs that don't match the real key.
    #[test]
    fn bad_sig_bad_buffer_returns_nte_bad_signature() {
        let prev = std::env::var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY").ok();
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");

        // 64-byte fake ECDSA P-256 signature (r||s format) and 32-byte fake CBOR.
        let fake_sig = vec![0xdeu8; 64];
        let fake_cbor = vec![0xadu8; 32];
        let result = verify_request_signature(&fake_sig, &fake_cbor);

        match prev {
            Some(v) => std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", v),
            None => std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY"),
        }

        assert_eq!(result, NTE_BAD_SIGNATURE,
            "bad sig + bad buffer must return NTE_BAD_SIGNATURE (key-fetch fails on Linux; \
             signature verify fails on Windows)");
    }

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

    /// `is_bypass_enabled` parses truthy values case-insensitively.
    #[test]
    fn bypass_enabled_truthy_values() {
        for val in &["1", "true", "TRUE", "True", "yes", "YES", "Yes"] {
            std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", val);
            assert!(is_bypass_enabled(), "expected true for value={val:?}");
        }
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");
    }

    /// `is_bypass_enabled` rejects falsy / unset values.
    #[test]
    fn bypass_enabled_falsy_values() {
        for val in &["0", "false", "FALSE", "no", "off", ""] {
            std::env::set_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY", val);
            assert!(!is_bypass_enabled(), "expected false for value={val:?}");
        }
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");

        // Also test unset.
        std::env::remove_var("KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY");
        assert!(!is_bypass_enabled(), "expected false when env var is unset");
    }
}
