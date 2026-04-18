//! PasskeeAuthenticator COM server — implements IPluginAuthenticator.
//!
//! IPluginAuthenticator is not in win32metadata, so we declare it using the
//! `windows::core` vtable primitives and implement it manually.
//!
//! Threading: STA (single-threaded apartment), matching the MSIX manifest
//! declaration `com:ThreadingModel="STA"`.
//!
//! Key invariant: the private key never leaves the KeePass plugin process.
//! This server only forwards CBOR-encoded CTAP2 requests over the IPC pipe
//! and returns the CBOR-encoded responses. It never sees raw key material.

#[cfg(windows)]
pub(crate) mod imp {
    use std::sync::{Arc, Mutex};

    use windows::core::{GUID, HRESULT};
    use windows::Win32::System::Com::{CoReleaseServerProcess, CoTaskMemAlloc};

    use crate::com::exe_server::sta_block_on;
    use crate::com::types::{
        PluginLockStatus, WebauthNPluginCancelOperationRequest,
        WebauthNPluginOperationRequest, WebauthNPluginOperationResponse,
        WebauthnPluginUserVerificationRequest,
    };
    use crate::com::webauthn_ext;
    use crate::ipc::{ClientError, PipeClient};

    /// E_ABORT HRESULT — user cancelled the UV prompt.
    const E_ABORT: u32 = 0x8000_4004;
    /// E_INVALIDARG HRESULT — best mapping for UnsupportedAlgorithm.
    const E_INVALIDARG: u32 = 0x8007_0057;
    /// ERROR_DUPLICATE_TAG HRESULT — best mapping for CredentialExcluded.
    const E_CREDENTIAL_EXCLUDED: u32 = 0x8007_0216;
    /// E_FAIL HRESULT — generic failure.
    const E_FAIL: u32 = 0x8000_4005;

    // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);

    // Canonical IID lives in com::types (cross-platform Guid). Convert on the fly.
    fn iid_iplugin_authenticator() -> GUID {
        windows::core::GUID::from(crate::com::types::IID_IPLUGIN_AUTHENTICATOR)
    }

    // ── IPluginAuthenticator vtable ───────────────────────────────────────────

    #[repr(C)]
    pub struct IUnknownVtbl {
        pub query_interface: unsafe extern "system" fn(*mut IPluginAuthenticatorImpl, *const GUID, *mut *mut std::ffi::c_void) -> HRESULT,
        pub add_ref: unsafe extern "system" fn(*mut IPluginAuthenticatorImpl) -> u32,
        pub release: unsafe extern "system" fn(*mut IPluginAuthenticatorImpl) -> u32,
    }

    #[repr(C)]
    pub struct IPluginAuthenticatorVtbl {
        pub iunknown: IUnknownVtbl,
        pub make_credential: unsafe extern "system" fn(
            *mut IPluginAuthenticatorImpl,
            *const WebauthNPluginOperationRequest,
            *mut WebauthNPluginOperationResponse,
        ) -> HRESULT,
        pub get_assertion: unsafe extern "system" fn(
            *mut IPluginAuthenticatorImpl,
            *const WebauthNPluginOperationRequest,
            *mut WebauthNPluginOperationResponse,
        ) -> HRESULT,
        pub cancel_operation: unsafe extern "system" fn(
            *mut IPluginAuthenticatorImpl,
            *const WebauthNPluginCancelOperationRequest,
        ) -> HRESULT,
        pub get_lock_status: unsafe extern "system" fn(
            *mut IPluginAuthenticatorImpl,
            *mut PluginLockStatus,
        ) -> HRESULT,
    }

    // ── COM object state ─────────────────────────────────────────────────────

    /// State shared between authenticator method dispatches. Protected by a
    /// `Mutex`, which is taken only briefly to acquire / return the pipe —
    /// never held across `sta_block_on` waits (doing so would deadlock a
    /// re-entrant COM dispatch on the same STA thread).
    pub struct PasskeeAuthenticatorState {
        #[allow(dead_code)]
        pub session_id: u32,
        pub pipe: Option<PipeClient>,
    }

    #[repr(C)]
    pub struct IPluginAuthenticatorImpl {
        pub vtbl: *const IPluginAuthenticatorVtbl,
        pub ref_count: std::sync::atomic::AtomicU32,
        pub state: Arc<Mutex<PasskeeAuthenticatorState>>,
    }

    impl IPluginAuthenticatorImpl {
        pub fn new(state: Arc<Mutex<PasskeeAuthenticatorState>>) -> Box<Self> {
            static VTBL: IPluginAuthenticatorVtbl = IPluginAuthenticatorVtbl {
                iunknown: IUnknownVtbl {
                    query_interface,
                    add_ref,
                    release,
                },
                make_credential,
                get_assertion,
                cancel_operation,
                get_lock_status,
            };
            Box::new(Self {
                vtbl: &VTBL,
                ref_count: std::sync::atomic::AtomicU32::new(1),
                state,
            })
        }
    }

    // ── IUnknown ─────────────────────────────────────────────────────────────

    unsafe extern "system" fn query_interface(
        this: *mut IPluginAuthenticatorImpl,
        riid: *const GUID,
        ppv: *mut *mut std::ffi::c_void,
    ) -> HRESULT {
        let iid = unsafe { &*riid };
        if *iid == IID_IUNKNOWN || *iid == iid_iplugin_authenticator() {
            unsafe { add_ref(this) };
            unsafe { *ppv = this as *mut _ };
            HRESULT(0)
        } else {
            unsafe { *ppv = std::ptr::null_mut() };
            HRESULT(0x8000_4002u32 as i32) // E_NOINTERFACE
        }
    }

    unsafe extern "system" fn add_ref(this: *mut IPluginAuthenticatorImpl) -> u32 {
        unsafe { (*this).ref_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1 }
    }

    unsafe extern "system" fn release(this: *mut IPluginAuthenticatorImpl) -> u32 {
        let prev = unsafe { (*this).ref_count.fetch_sub(1, std::sync::atomic::Ordering::Release) };
        if prev == 1 {
            std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
            let _ = unsafe { Box::from_raw(this) };
            // Balance CoAddRefServerProcess() from cf_create_instance.
            // When this brings the server refcount to zero, CoReleaseServerProcess
            // internally calls CoSuspendClassObjects + PostQuitMessage, which
            // unblocks run_com_server's GetMessageW loop.
            unsafe { CoReleaseServerProcess() };
            return 0;
        }
        prev - 1
    }

    // ── IPluginAuthenticator ─────────────────────────────────────────────────

    unsafe extern "system" fn make_credential(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginOperationRequest,
        response: *mut WebauthNPluginOperationResponse,
    ) -> HRESULT {
        unsafe { dispatch_operation(this, request, response, "passkee.makeCredentialRaw") }
    }

    unsafe extern "system" fn get_assertion(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginOperationRequest,
        response: *mut WebauthNPluginOperationResponse,
    ) -> HRESULT {
        unsafe { dispatch_operation(this, request, response, "passkee.getAssertionRaw") }
    }

    unsafe extern "system" fn cancel_operation(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginCancelOperationRequest,
    ) -> HRESULT {
        let obj = unsafe { &*this };
        let req = unsafe { &*request };
        let txn = format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            req.transaction_id.data1, req.transaction_id.data2, req.transaction_id.data3,
            req.transaction_id.data4[0], req.transaction_id.data4[1],
            req.transaction_id.data4[2], req.transaction_id.data4[3],
            req.transaction_id.data4[4], req.transaction_id.data4[5],
            req.transaction_id.data4[6], req.transaction_id.data4[7],
        );

        // Take pipe out of state, release lock before STA-pumping wait.
        let pipe_opt = { obj.state.lock().unwrap().pipe.take() };
        let mut pipe = match pipe_opt {
            Some(p) => p,
            // Pipe already in use by another dispatch (re-entrant case) or not
            // connected. Report success — a cancellation that can't reach the
            // vault is treated as a best-effort signal, not a hard error.
            None => return HRESULT(0),
        };

        let params = serde_json::json!({ "transactionId": txn });
        let (_result, pipe_back): (std::result::Result<serde_json::Value, ClientError>, PipeClient) =
            sta_block_on(async move {
                let r = pipe.call("passkee.cancelOperation", params).await;
                (r, pipe)
            });

        obj.state.lock().unwrap().pipe = Some(pipe_back);
        HRESULT(0)
    }

    unsafe extern "system" fn get_lock_status(
        this: *mut IPluginAuthenticatorImpl,
        lock_status: *mut PluginLockStatus,
    ) -> HRESULT {
        let obj = unsafe { &*this };

        let pipe_opt = { obj.state.lock().unwrap().pipe.take() };
        let mut pipe = match pipe_opt {
            Some(p) => p,
            None => {
                unsafe { *lock_status = PluginLockStatus::Locked };
                return HRESULT(0);
            }
        };

        let (result, pipe_back): (std::result::Result<serde_json::Value, ClientError>, PipeClient) =
            sta_block_on(async move {
                let r = pipe.call("passkee.getLockStatus", serde_json::json!({})).await;
                (r, pipe)
            });

        obj.state.lock().unwrap().pipe = Some(pipe_back);

        match result {
            Ok(v) => {
                let locked = v["locked"].as_bool().unwrap_or(true);
                unsafe {
                    *lock_status = if locked { PluginLockStatus::Locked } else { PluginLockStatus::Unlocked };
                }
                HRESULT(0)
            }
            Err(ClientError::VaultLocked) => {
                unsafe { *lock_status = PluginLockStatus::Locked };
                HRESULT(0)
            }
            Err(_) => HRESULT(0x8000_4005u32 as i32), // E_FAIL
        }
    }

    unsafe fn dispatch_operation(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginOperationRequest,
        response: *mut WebauthNPluginOperationResponse,
        method: &str,
    ) -> HRESULT {
        use base64::Engine;

        let obj = unsafe { &*this };
        let req = unsafe { &*request };
        let cbor_bytes = unsafe { req.encoded_request() };
        let cbor_b64 = base64::engine::general_purpose::STANDARD.encode(cbor_bytes);

        // ── Step 1: extract UV prompt hint from CBOR ──────────────────────────
        // For MakeCredential the CTAP2 request contains `user.name` (key 3).
        // For GetAssertion (and any future operation) we fall back to "PassKee".
        // A failed parse also falls back so a malformed CBOR still triggers UV
        // and lets the C# side produce the proper error code.
        let username_hint = extract_prompt_hint(cbor_bytes, method);

        // UTF-16 owned buffers — kept alive across the UV call.
        let username_w: Vec<u16> = username_hint.encode_utf16().chain(std::iter::once(0)).collect();
        let display_hint_w: Vec<u16> = "PassKee\0".encode_utf16().collect();

        // ── Step 2: call PerformUserVerification (inline on STA thread) ───────
        // Windows pumps its own dialog messages internally. Do NOT wrap in
        // sta_block_on — that's for async pipe I/O, not blocking UI calls.
        //
        // p_transaction_id is REFGUID (pointer), NOT inline. We take the
        // address of the transactionId field on the incoming operation
        // request; `req` is a `&WebauthNPluginOperationRequest` owned by
        // webauthn.dll for the duration of this COM call, so the pointer
        // is valid until we return. See the `WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST`
        // doc comment in types.rs for the Session 6 crash archaeology.
        let uv_request = WebauthnPluginUserVerificationRequest {
            hwnd:              req.hwnd,
            p_transaction_id:  &req.transaction_id as *const _,
            pwsz_username:     username_w.as_ptr(),
            pwsz_display_hint: display_hint_w.as_ptr(),
        };

        let mut cb_uv_response: u32 = 0;
        let mut pb_uv_response: *mut u8 = std::ptr::null_mut();

        let uv_hr = match webauthn_ext::perform_user_verification(
            &uv_request, &mut cb_uv_response, &mut pb_uv_response,
        ) {
            Ok(hr) => hr,
            Err(_e) => {
                // Bindings not loaded — shouldn't happen post-registration, but
                // fail gracefully.
                return HRESULT(E_FAIL as i32);
            }
        };

        // Free the UV response on EVERY exit path from here on.
        // We don't verify the UV signature (Phase 5 deferred — see MEMORY.md).
        webauthn_ext::free_user_verification_response(pb_uv_response);

        if uv_hr.0 as u32 == E_ABORT {
            // User cancelled the UV prompt — propagate E_ABORT to the caller.
            return uv_hr;
        }
        if uv_hr.is_err() {
            // Other UV failure — propagate.
            return uv_hr;
        }

        // ── Step 3: UV succeeded — forward to the C# plugin via IPC ──────────
        // Always pass `"uv": true` — UV failure would have aborted above.

        // Take pipe out of state, release lock before STA-pumping wait. Never
        // hold the state mutex across sta_block_on — doing so would deadlock
        // any re-entrant COM dispatch on the same STA thread.
        let pipe_opt = { obj.state.lock().unwrap().pipe.take() };
        let mut pipe = match pipe_opt {
            Some(p) => p,
            None => return HRESULT(E_FAIL as i32),
        };

        let params = serde_json::json!({ "cbor": cbor_b64, "uv": true });
        let method_owned = method.to_string();
        let (result, pipe_back): (std::result::Result<serde_json::Value, ClientError>, PipeClient) =
            sta_block_on(async move {
                let r = pipe.call(&method_owned, params).await;
                (r, pipe)
            });

        obj.state.lock().unwrap().pipe = Some(pipe_back);

        match result {
            Ok(v) => {
                let resp_b64 = match v["cbor"].as_str() {
                    Some(s) => s.to_owned(),
                    None => return HRESULT(E_FAIL as i32),
                };
                let resp_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&resp_b64)
                    .unwrap_or_default();

                let buf = unsafe { CoTaskMemAlloc(resp_bytes.len()) as *mut u8 };
                if buf.is_null() {
                    return HRESULT(0x8007_000Eu32 as i32); // E_OUTOFMEMORY
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(resp_bytes.as_ptr(), buf, resp_bytes.len());
                    (*response).cb_encoded_response = resp_bytes.len() as u32;
                    (*response).pb_encoded_response = buf;
                }
                HRESULT(0)
            }
            Err(ClientError::VaultLocked)         => HRESULT(0x8007_0005u32 as i32), // E_ACCESSDENIED
            Err(ClientError::UnsupportedAlgorithm) => HRESULT(E_INVALIDARG as i32),
            Err(ClientError::CredentialExcluded)   => HRESULT(E_CREDENTIAL_EXCLUDED as i32),
            Err(_)                                 => HRESULT(E_FAIL as i32),
        }
    }

    /// Attempt to extract a user-visible prompt hint from the raw CBOR bytes.
    ///
    /// For `passkee.makeCredentialRaw` the bytes are a CTAP2 `authenticatorMakeCredential`
    /// map (keys 1-9). Key 3 is `user`, whose `name` field becomes the UV prompt
    /// username. On any parse failure — or for operations that don't carry a username
    /// (GetAssertion) — returns `"PassKee"` as the fallback display string.
    pub(crate) fn extract_prompt_hint(cbor_bytes: &[u8], _method: &str) -> String {
        use passkey_types::ctap2::make_credential::Request as MakeCredentialRequest;
        match ciborium::de::from_reader::<MakeCredentialRequest, _>(cbor_bytes) {
            Ok(req) => req.user.name,
            Err(_)  => "PassKee".to_string(),
        }
    }
}

// ── Cross-platform tests ──────────────────────────────────────────────────────

// Note: the COM-method tests above test the types and const values.
// Tests for extract_prompt_hint live here because they are cross-platform
// (ciborium + passkey-types work on Linux) and the function itself is
// declared inside the #[cfg(windows)] `imp` block — we expose it with
// `pub(crate)` and cfg-gate the tests.

#[cfg(test)]
mod prompt_hint_tests {
    #[cfg(windows)]
    use super::imp::extract_prompt_hint;

    /// Helper: encode a MakeCredential request with the given user.name and
    /// return the CBOR bytes. Used to produce canonical test vectors without
    /// hard-coding raw bytes.
    #[cfg(windows)]
    fn make_credential_cbor(user_name: &str) -> Vec<u8> {
        use passkey_types::{
            ctap2::make_credential::Request,
            Bytes,
            webauthn::{PublicKeyCredentialUserEntity, PublicKeyCredentialRpEntity,
                        PublicKeyCredentialParameters, PublicKeyCredentialType},
        };
        use passkey_types::ctap2::make_credential::PublicKeyCredentialRpEntity as CtapRpEntity;
        use coset::iana::Algorithm;

        let req = Request {
            client_data_hash: Bytes::from(vec![0u8; 32]),
            rp: CtapRpEntity {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: PublicKeyCredentialUserEntity {
                id: Bytes::from(vec![1u8, 2, 3]),
                name: user_name.to_string(),
                display_name: "Test User".to_string(),
            },
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                ty: PublicKeyCredentialType::PublicKey,
                alg: coset::iana::Algorithm::ES256,
            }],
            exclude_list: None,
            extensions: None,
            options: Default::default(),
            pin_auth: None,
            pin_protocol: None,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&req, &mut buf).expect("cbor encode");
        buf
    }

    #[cfg(windows)]
    #[test]
    fn extract_hint_from_make_credential() {
        let cbor = make_credential_cbor("alice@example.com");
        assert_eq!(extract_prompt_hint(&cbor, "passkee.makeCredentialRaw"), "alice@example.com");
    }

    #[cfg(windows)]
    #[test]
    fn extract_hint_malformed_cbor_fallback() {
        // A truncated / garbage CBOR blob should not panic and returns "PassKee".
        let bad = b"\xff\x00\x01garbage";
        assert_eq!(extract_prompt_hint(bad, "passkee.makeCredentialRaw"), "PassKee");
    }

    #[cfg(windows)]
    #[test]
    fn extract_hint_get_assertion_fallback() {
        // GetAssertion CBOR is a different map shape — parsing as MakeCredential fails → "PassKee".
        // Construct a minimal GetAssertion CBOR (key 1 = rpId string).
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![
                (ciborium::value::Value::Integer(1.into()), ciborium::value::Value::Text("example.com".to_string())),
            ]),
            &mut buf,
        ).unwrap();
        assert_eq!(extract_prompt_hint(&buf, "passkee.getAssertionRaw"), "PassKee");
    }
}

// ── From impl: cross-platform Guid → windows::core::GUID ────────────────────

#[cfg(windows)]
impl From<crate::com::types::Guid> for windows::core::GUID {
    fn from(g: crate::com::types::Guid) -> Self {
        // Reconstruct the u128 from the GUID fields (big-endian field assembly
        // matching the GUID layout: data1(32) + data2(16) + data3(16) + data4[8]).
        let hi = ((g.data1 as u128) << 96)
            | ((g.data2 as u128) << 80)
            | ((g.data3 as u128) << 64)
            | ((g.data4[0] as u128) << 56)
            | ((g.data4[1] as u128) << 48)
            | ((g.data4[2] as u128) << 40)
            | ((g.data4[3] as u128) << 32)
            | ((g.data4[4] as u128) << 24)
            | ((g.data4[5] as u128) << 16)
            | ((g.data4[6] as u128) << 8)
            |  (g.data4[7] as u128);
        windows::core::GUID::from_u128(hi)
    }
}

// ── Cross-platform tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::com::types::*;

    #[test]
    fn iid_constant_correct() {
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data1, 0xd26b_cf6f);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data2, 0xb54c);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data3, 0x43ff);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data4, [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7]);
    }

    #[test]
    fn plugin_lock_status_values() {
        assert_eq!(PluginLockStatus::Locked as u32, 0);
        assert_eq!(PluginLockStatus::Unlocked as u32, 1);
    }

    #[test]
    fn request_type_cbor_value() {
        assert_eq!(WebauthNPluginRequestType::Ctap2Cbor as u32, 1);
    }
}
