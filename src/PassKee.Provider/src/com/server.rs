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
    use windows::Win32::System::Com::CoTaskMemAlloc;

    use crate::com::types::{
        PluginLockStatus, WebauthNPluginCancelOperationRequest,
        WebauthNPluginOperationRequest, WebauthNPluginOperationResponse,
    };
    use crate::ipc::{ClientError, PipeClient};

    // IID_IPluginAuthenticator = {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
    pub const IID_IPLUGIN_AUTHENTICATOR: GUID = GUID::from_u128(0xd26bcf6f_b54c_43ff_9f06_d5bf148625f7);
    // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);

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

    pub struct PasskeeAuthenticatorState {
        #[allow(dead_code)]
        pub session_id: u32,
        pub pipe: Option<PipeClient>,
        pub runtime: tokio::runtime::Runtime,
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
        if *iid == IID_IUNKNOWN || *iid == IID_IPLUGIN_AUTHENTICATOR {
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

        let mut guard = obj.state.lock().unwrap();
        let params = serde_json::json!({ "transactionId": txn });
        if guard.pipe.is_some() {
            // Take pipe out temporarily to satisfy borrow checker — runtime + pipe both from guard.
            let mut pipe = guard.pipe.take().unwrap();
            let _: std::result::Result<serde_json::Value, _> = guard.runtime.block_on(async {
                pipe.call("passkee.cancelOperation", params).await
            });
            guard.pipe = Some(pipe);
        }
        HRESULT(0)
    }

    unsafe extern "system" fn get_lock_status(
        this: *mut IPluginAuthenticatorImpl,
        lock_status: *mut PluginLockStatus,
    ) -> HRESULT {
        let obj = unsafe { &*this };
        let mut guard = obj.state.lock().unwrap();

        if guard.pipe.is_none() {
            unsafe { *lock_status = PluginLockStatus::Locked };
            return HRESULT(0);
        }

        let mut pipe = guard.pipe.take().unwrap();
        let result: std::result::Result<serde_json::Value, ClientError> =
            guard.runtime.block_on(async {
                pipe.call("passkee.getLockStatus", serde_json::json!({})).await
            });
        guard.pipe = Some(pipe);

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

        let mut guard = obj.state.lock().unwrap();
        if guard.pipe.is_none() {
            return HRESULT(0x8000_4005u32 as i32); // E_FAIL
        }

        // Take pipe to avoid simultaneous mut+immut borrow of guard.
        let mut pipe = guard.pipe.take().unwrap();
        let params = serde_json::json!({ "cbor": cbor_b64 });
        let result: std::result::Result<serde_json::Value, ClientError> =
            guard.runtime.block_on(async { pipe.call(method, params).await });
        guard.pipe = Some(pipe);

        match result {
            Ok(v) => {
                let resp_b64 = match v["cbor"].as_str() {
                    Some(s) => s.to_owned(),
                    None => return HRESULT(0x8000_4005u32 as i32),
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
            Err(ClientError::VaultLocked) => HRESULT(0x8007_0005u32 as i32), // E_ACCESSDENIED
            Err(_) => HRESULT(0x8000_4005u32 as i32),
        }
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
