//! COM DLL entry points: DllGetClassObject, DllCanUnloadNow,
//! DllRegisterServer, DllUnregisterServer.
//!
//! CLSID for PasskeeAuthenticator:
//!   {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    };

    use windows::core::{GUID, HRESULT};

    use crate::com::server::imp::{
        IPluginAuthenticatorImpl,
        PasskeeAuthenticatorState, IID_IPLUGIN_AUTHENTICATOR,
    };

    // IID_IClassFactory = {00000001-0000-0000-C000-000000000046}
    const IID_ICLASS_FACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);
    // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);

    static OUTSTANDING_OBJECTS: AtomicU32 = AtomicU32::new(0);

    // ── IClassFactory vtable ──────────────────────────────────────────────────

    #[repr(C)]
    struct ClassFactoryVtbl {
        query_interface: unsafe extern "system" fn(*mut ClassFactory, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref: unsafe extern "system" fn(*mut ClassFactory) -> u32,
        release: unsafe extern "system" fn(*mut ClassFactory) -> u32,
        create_instance: unsafe extern "system" fn(*mut ClassFactory, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
        lock_server: unsafe extern "system" fn(*mut ClassFactory, i32) -> HRESULT,
    }

    #[repr(C)]
    struct ClassFactory {
        vtbl: *const ClassFactoryVtbl,
        ref_count: AtomicU32,
        session_id: u32,
    }

    impl ClassFactory {
        fn new(session_id: u32) -> Box<Self> {
            static VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
                query_interface: cf_query_interface,
                add_ref: cf_add_ref,
                release: cf_release,
                create_instance: cf_create_instance,
                lock_server: cf_lock_server,
            };
            Box::new(Self { vtbl: &VTBL, ref_count: AtomicU32::new(1), session_id })
        }
    }

    unsafe extern "system" fn cf_query_interface(
        this: *mut ClassFactory, riid: *const GUID, ppv: *mut *mut c_void,
    ) -> HRESULT {
        let iid = unsafe { &*riid };
        if *iid == IID_IUNKNOWN || *iid == IID_ICLASS_FACTORY {
            unsafe { cf_add_ref(this) };
            unsafe { *ppv = this as *mut _ };
            HRESULT(0)
        } else {
            unsafe { *ppv = std::ptr::null_mut() };
            HRESULT(0x8000_4002u32 as i32) // E_NOINTERFACE
        }
    }

    unsafe extern "system" fn cf_add_ref(this: *mut ClassFactory) -> u32 {
        unsafe { (*this).ref_count.fetch_add(1, Ordering::Relaxed) + 1 }
    }

    unsafe extern "system" fn cf_release(this: *mut ClassFactory) -> u32 {
        let prev = unsafe { (*this).ref_count.fetch_sub(1, Ordering::Release) };
        if prev == 1 {
            std::sync::atomic::fence(Ordering::Acquire);
            let _ = unsafe { Box::from_raw(this) };
            return 0;
        }
        prev - 1
    }

    unsafe extern "system" fn cf_create_instance(
        this: *mut ClassFactory, _outer: *mut c_void, riid: *const GUID, ppv: *mut *mut c_void,
    ) -> HRESULT {
        let session_id = unsafe { (*this).session_id };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let pipe = runtime.block_on(crate::ipc::PipeClient::connect(session_id)).ok();

        let state = Arc::new(Mutex::new(PasskeeAuthenticatorState { session_id, pipe, runtime }));
        let obj = IPluginAuthenticatorImpl::new(state);
        let raw = Box::into_raw(obj);

        OUTSTANDING_OBJECTS.fetch_add(1, Ordering::Relaxed);

        // Route through QueryInterface.
        let vtbl = unsafe { &*(*raw).vtbl };
        let hr = unsafe { (vtbl.iunknown.query_interface)(raw, riid, ppv) };
        if hr.is_err() {
            let _ = unsafe { Box::from_raw(raw) };
            OUTSTANDING_OBJECTS.fetch_sub(1, Ordering::Relaxed);
        }
        hr
    }

    unsafe extern "system" fn cf_lock_server(this: *mut ClassFactory, lock: i32) -> HRESULT {
        let _ = this;
        if lock != 0 { OUTSTANDING_OBJECTS.fetch_add(1, Ordering::Relaxed); }
        else          { OUTSTANDING_OBJECTS.fetch_sub(1, Ordering::Relaxed); }
        HRESULT(0)
    }

    // ── DLL exports ───────────────────────────────────────────────────────────

    #[no_mangle]
    pub unsafe extern "system" fn DllGetClassObject(
        rclsid: *const GUID, riid: *const GUID, ppv: *mut *mut c_void,
    ) -> HRESULT {
        let clsid = unsafe { &*rclsid };
        if *clsid != IID_IPLUGIN_AUTHENTICATOR {
            return HRESULT(0x8004_0154u32 as i32); // REGDB_E_CLASSNOTREG
        }

        // Derive session ID from the current process.
        let session_id = get_session_id();

        let factory = ClassFactory::new(session_id);
        let raw = Box::into_raw(factory);
        let hr = unsafe { cf_query_interface(raw, riid, ppv) };
        if hr.is_err() {
            let _ = unsafe { Box::from_raw(raw) };
        }
        hr
    }

    #[no_mangle]
    pub extern "system" fn DllCanUnloadNow() -> HRESULT {
        if OUTSTANDING_OBJECTS.load(Ordering::Relaxed) == 0 { HRESULT(0) } else { HRESULT(1) }
    }

    #[no_mangle]
    pub extern "system" fn DllRegisterServer() -> HRESULT {
        HRESULT(0) // No-op on MSIX — manifest handles registration.
    }

    #[no_mangle]
    pub extern "system" fn DllUnregisterServer() -> HRESULT {
        HRESULT(0)
    }

    fn get_session_id() -> u32 {
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let mut sid = 0u32;
        let _ = unsafe { ProcessIdToSessionId(pid, &mut sid) };
        sid
    }
}

#[cfg(windows)]
pub use imp::{DllCanUnloadNow, DllGetClassObject, DllRegisterServer, DllUnregisterServer};
