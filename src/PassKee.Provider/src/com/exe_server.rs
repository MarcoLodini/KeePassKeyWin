//! EXE-server entry points and ClassFactory for IPluginAuthenticator.
//!
//! The Windows WebAuthn host activates PassKee via
//!   CoCreateInstance(CLSID_PassKee, CLSCTX_LOCAL_SERVER, ...)
//! which causes the OS to launch `passkee-provider.exe -PluginActivated`.
//! The EXE then calls `run_com_server()` which registers the ClassFactory on
//! an STA and pumps messages until the last object is released.
//!
//! CLSID_PassKee = IID_IPluginAuthenticator = {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
//!
//! Lifecycle integration:
//!   - `cf_create_instance` calls `CoAddRefServerProcess()` when handing out an
//!     authenticator object (paired with `CoReleaseServerProcess()` in that
//!     object's final Release — see `com::server`).
//!   - `cf_lock_server(TRUE/FALSE)` wraps `CoAddRefServerProcess` /
//!     `CoReleaseServerProcess` per the standard IClassFactory::LockServer
//!     pattern.
//!   - When the server reference count reaches zero, `CoReleaseServerProcess`
//!     internally posts `WM_QUIT` to the calling thread, which (under STA)
//!     is the same thread running `run_com_server`'s message pump. The pump
//!     then exits cleanly.
//!
//! STA re-entrancy: `sta_block_on()` replaces raw `runtime.block_on(...)` so
//! pipe I/O does not starve the message pump. Any re-entrant COM calls that
//! arrive during the wait (for example a `CancelOperation` from the host) are
//! dispatched via the hidden window messages queued by the COM marshaling
//! layer.

#[cfg(windows)]
pub(crate) mod imp {
    use std::ffi::c_void;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, OnceLock,
    };

    use windows::core::{GUID, HRESULT};
    use windows::Win32::System::Com::{
        CoAddRefServerProcess, CoReleaseServerProcess,
    };

    use crate::com::server::imp::{
        IPluginAuthenticatorImpl,
        PasskeeAuthenticatorState,
    };

    // IID_IClassFactory = {00000001-0000-0000-C000-000000000046}
    const IID_ICLASS_FACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);
    // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);
    // CLSID_PassKee = IID_IPluginAuthenticator = {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
    pub(crate) const CLSID_PASSKEE: GUID = GUID::from_u128(0xd26bcf6f_b54c_43ff_9f06_d5bf148625f7);

    /// Shared Tokio runtime. Populated by `run_com_server` before the class
    /// factory is registered; consumed by `cf_create_instance` and
    /// `sta_block_on`.
    pub static RT: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();

    /// Thread ID of the STA running the message pump. Zero until
    /// `run_com_server` captures it.
    pub static STA_THREAD_ID: AtomicU32 = AtomicU32::new(0);

    // ── IClassFactory vtable ──────────────────────────────────────────────────

    #[repr(C)]
    pub(crate) struct ClassFactoryVtbl {
        query_interface: unsafe extern "system" fn(*mut ClassFactory, *const GUID, *mut *mut c_void) -> HRESULT,
        add_ref:         unsafe extern "system" fn(*mut ClassFactory) -> u32,
        release:         unsafe extern "system" fn(*mut ClassFactory) -> u32,
        create_instance: unsafe extern "system" fn(*mut ClassFactory, *mut c_void, *const GUID, *mut *mut c_void) -> HRESULT,
        lock_server:     unsafe extern "system" fn(*mut ClassFactory, i32) -> HRESULT,
    }

    #[repr(C)]
    pub(crate) struct ClassFactory {
        vtbl:      *const ClassFactoryVtbl,
        ref_count: AtomicU32,
        session_id: u32,
    }

    impl ClassFactory {
        fn new(session_id: u32) -> Box<Self> {
            static VTBL: ClassFactoryVtbl = ClassFactoryVtbl {
                query_interface: cf_query_interface,
                add_ref:         cf_add_ref,
                release:         cf_release,
                create_instance: cf_create_instance,
                lock_server:     cf_lock_server,
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
            // NOTE: no CoReleaseServerProcess here — the class-factory lifetime
            // is independent of the server-object refcount. Server-process
            // lifetime is accounted for by cf_create_instance/authenticator
            // release and cf_lock_server.
            return 0;
        }
        prev - 1
    }

    unsafe extern "system" fn cf_create_instance(
        this: *mut ClassFactory, _outer: *mut c_void, riid: *const GUID, ppv: *mut *mut c_void,
    ) -> HRESULT {
        use std::io::Write;
        macro_rules! dbg_step { ($($arg:tt)*) => {{
            eprintln!("[activate] {}", format_args!($($arg)*));
            let _ = std::io::stderr().flush();
        }} }

        let session_id = unsafe { (*this).session_id };
        dbg_step!("cf_create_instance session_id={session_id}");

        // Pull the shared runtime. Panic is intentional — only reachable after
        // run_com_server has populated RT.
        let runtime = RT.get().expect("runtime uninitialised").clone();

        // Connect the pipe AND complete the passkee.hello handshake before
        // handing the authenticator object to the caller. The plugin-side
        // RpcDispatcher rejects every non-`passkee.hello` method until the
        // per-connection ConnectionContext has HandshakeComplete=true, so
        // without this we can't dispatch anything.
        //
        // Concurrency note: the HKCU nonce is read by THIS activation, then
        // consumed + rotated by the plugin on our handshake call. If two
        // browser registrations activate two sidecars concurrently, both
        // read the same nonce; the first handshake wins, the second gets
        // HandshakeInvalid and drops the pipe. Not a v1 concern — browsers
        // don't register concurrently. Documented in MEMORY.md.
        let pipe = runtime.block_on(async {
            let mut p = match crate::ipc::PipeClient::connect(session_id).await {
                Ok(p)  => { dbg_step!("pipe connect OK"); p }
                Err(e) => { dbg_step!("pipe connect FAILED: {e}"); return None; }
            };
            let nonce = match read_handshake_nonce() {
                Some(n) => {
                    let prefix: String = n.chars().take(8).collect();
                    dbg_step!("read nonce from HKCU: \"{prefix}...\" ({} chars)", n.len());
                    n
                }
                None => {
                    dbg_step!("read nonce FAILED — HKCU\\Software\\PassKee\\HandshakeNonce missing");
                    return None;
                }
            };
            match p.handshake(PASSKEE_PKG_FAMILY, &nonce).await {
                Ok(())  => { dbg_step!("handshake OK"); Some(p) }
                Err(e)  => { dbg_step!("handshake FAILED: {e:?}"); None }
            }
        });

        let state = Arc::new(Mutex::new(PasskeeAuthenticatorState { session_id, pipe }));
        let obj = IPluginAuthenticatorImpl::new(state);
        let raw = Box::into_raw(obj);

        // Increment the process ref count BEFORE the caller gets the object.
        // Balanced by the authenticator's Release in com::server.
        unsafe { CoAddRefServerProcess() };

        // Route through QueryInterface.
        let vtbl = unsafe { &*(*raw).vtbl };
        let hr = unsafe { (vtbl.iunknown.query_interface)(raw, riid, ppv) };
        if hr.is_err() {
            let _ = unsafe { Box::from_raw(raw) };
            unsafe { CoReleaseServerProcess() };
        }
        hr
    }

    /// Our MSIX package family name. Must match
    /// `PassKee.Core.Ipc.HandshakeHandler.ExpectedPkgFamily` on the C# side
    /// — the plugin rejects handshakes from any other PFN. If the package
    /// publisher identity ever changes this constant and the C# constant
    /// MUST be updated in lockstep.
    pub(crate) const PASSKEE_PKG_FAMILY: &str = "PassKee.Provider_rh4edrm0by30m";

    /// Read the current handshake nonce from
    /// `HKCU\Software\PassKee\HandshakeNonce`. The plugin writes it on
    /// startup and rotates on each successful consume. Returns `None` on
    /// any error (missing key, wrong type, registry failure) — the caller
    /// treats a missing nonce the same as a handshake failure.
    pub(crate) fn read_handshake_nonce() -> Option<String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ,
        };

        let sub_key: Vec<u16>    = "Software\\PassKee\0".encode_utf16().collect();
        let value_name: Vec<u16> = "HandshakeNonce\0".encode_utf16().collect();

        // Nonce is 64 hex chars + null = 130 bytes. 512 is plenty.
        let mut buf: [u16; 256] = [0u16; 256];
        let mut cb: u32 = (buf.len() * 2) as u32;

        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(sub_key.as_ptr()),
                PCWSTR(value_name.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buf.as_mut_ptr() as *mut _),
                Some(&mut cb),
            )
        };
        if status.is_err() {
            return None;
        }
        // cb is bytes written including the trailing UTF-16 null.
        let wchars = (cb as usize) / 2;
        let end = buf[..wchars].iter().position(|&c| c == 0).unwrap_or(wchars);
        String::from_utf16(&buf[..end]).ok()
    }

    unsafe extern "system" fn cf_lock_server(_this: *mut ClassFactory, lock: i32) -> HRESULT {
        // Standard LockServer implementation per MS guidance.
        if lock != 0 {
            unsafe { CoAddRefServerProcess() };
        } else {
            unsafe { CoReleaseServerProcess() };
        }
        HRESULT(0)
    }

    // ── Public factory helper ─────────────────────────────────────────────────

    pub(super) fn new_class_factory(session_id: u32) -> Box<ClassFactory> {
        ClassFactory::new(session_id)
    }

    // ── Session ID helper ─────────────────────────────────────────────────────

    pub(crate) fn get_session_id() -> u32 {
        use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let mut sid = 0u32;
        let _ = unsafe { ProcessIdToSessionId(pid, &mut sid) };
        sid
    }
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Run the EXE as an out-of-process COM class factory (STA).
///
/// Sequence (MS-documented out-of-proc server pattern):
///   1. Build the shared Tokio runtime (so SCM never waits on tokio init).
///   2. `CoInitializeEx(STA)`.
///   3. Capture the STA thread ID for diagnostics.
///   4. Build ClassFactory.
///   5. `CoRegisterClassObject(CLSID, IUnknown, CLSCTX_LOCAL_SERVER,
///       REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED)`.
///   6. `CoResumeClassObjects()` — allow activations.
///   7. `GetMessageW` / `TranslateMessage` / `DispatchMessageW` pump until
///      `WM_QUIT` arrives (posted by `CoReleaseServerProcess` when the last
///      authenticator is released).
///   8. `CoRevokeClassObject(cookie)` → Release our factory ref →
///      `CoUninitialize` → `process::exit(0)`.
#[cfg(windows)]
pub fn run_com_server() -> ! {
    use std::sync::atomic::Ordering;
    use windows::core::{IUnknown, Interface};
    use windows::Win32::System::Com::{
        CoInitializeEx, CoRegisterClassObject, CoResumeClassObjects, CoRevokeClassObject,
        CoUninitialize, CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED,
        REGCLS_MULTIPLEUSE, REGCLS_SUSPENDED,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetMessageW, TranslateMessage, MSG,
    };

    // 1. Build shared tokio runtime BEFORE any COM call — SCM is watching.
    let rt = std::sync::Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );
    // OK to ignore — we're the only caller.
    let _ = imp::RT.set(rt);

    // 2. STA init.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .expect("CoInitializeEx(STA) failed");
    }

    // 3. Capture STA thread ID (diagnostic; not functionally required because
    // CoReleaseServerProcess posts WM_QUIT to the calling thread on zero-ref).
    imp::STA_THREAD_ID.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);

    // 4. Build ClassFactory. ref_count starts at 1 per ClassFactory::new.
    let session_id = imp::get_session_id();
    let factory_box = imp::new_class_factory(session_id);
    let factory_raw = Box::into_raw(factory_box) as *mut std::ffi::c_void;

    // 5. Wrap as IUnknown. from_raw takes ownership of the ref — it does NOT
    // AddRef. When iunk drops, its vtable Release is called, decrementing
    // our ref count. First three vtable slots of ClassFactoryVtbl match
    // IUnknownVtbl, so dispatch is ABI-compatible.
    let iunk = unsafe { IUnknown::from_raw(factory_raw) };

    // 6. Register class object + resume. In windows-rs 0.61 this returns the
    // cookie as Result<u32> rather than taking it as an out-param.
    let cookie: u32 = unsafe {
        CoRegisterClassObject(
            &imp::CLSID_PASSKEE,
            &iunk,
            CLSCTX_LOCAL_SERVER,
            REGCLS_MULTIPLEUSE | REGCLS_SUSPENDED,
        )
        .expect("CoRegisterClassObject failed")
    };
    unsafe { CoResumeClassObjects().expect("CoResumeClassObjects failed") };

    // 7. STA message pump.
    let mut msg = MSG::default();
    loop {
        let r = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        // 0 = WM_QUIT, -1 = error. Either way, exit.
        if r.0 == 0 || r.0 == -1 {
            break;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // 8. Shutdown. CoRevokeClassObject releases COM's factory ref; drop(iunk)
    // releases ours (ref → 0 → ClassFactory freed via Box::from_raw in cf_release).
    unsafe {
        let _ = CoRevokeClassObject(cookie);
    }
    drop(iunk);

    unsafe { CoUninitialize() };
    std::process::exit(0);
}

/// STA-safe `block_on`: spawn `fut` onto the shared Tokio runtime, then wait
/// on an event via `CoWaitForMultipleHandles` so the STA message pump keeps
/// running. Returns `fut`'s output when it completes.
///
/// Why not `runtime.block_on`: on an STA thread, `block_on` parks the thread
/// entirely — any re-entrant COM call (for example a `CancelOperation`
/// dispatched by the WebAuthn host while `MakeCredential` is still in flight)
/// arrives as a window message and cannot be delivered. `CoWaitForMultipleHandles`
/// pumps those messages while waiting on our completion event.
#[cfg(windows)]
pub fn sta_block_on<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use std::sync::mpsc::sync_channel;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Com::CoWaitForMultipleHandles;
    use windows::Win32::System::Threading::{CreateEventW, SetEvent, INFINITE};

    // Auto-reset (manual_reset = false), initially non-signaled, unnamed.
    // In windows-rs 0.61, CreateEventW takes Rust bool (gated behind Win32_Security).
    let event: HANDLE = unsafe {
        CreateEventW(None, false, false, None).expect("CreateEventW failed")
    };

    // HANDLE's inner ptr isn't Send; pass the raw integer across threads.
    let event_raw = event.0 as isize;
    let (tx, rx) = sync_channel::<T>(1);

    imp::RT
        .get()
        .expect("tokio runtime not initialised")
        .spawn(async move {
            // Catch panics from `fut` so SetEvent still fires. Without this,
            // a panic would drop `tx` (no send) AND skip SetEvent → the STA
            // thread's CoWaitForMultipleHandles(INFINITE) would hang forever.
            let result = std::panic::AssertUnwindSafe(fut);
            let outcome = futures::FutureExt::catch_unwind(result).await;
            if let Ok(v) = outcome {
                let _ = tx.send(v);
            }
            // Always signal — even on panic or channel-send failure — so the
            // STA thread unblocks. It will observe `rx.recv() == Err(...)`
            // and map that to an HRESULT.
            let h = HANDLE(event_raw as *mut _);
            unsafe {
                let _ = SetEvent(h);
            }
        });

    // dwFlags = 0 (COWAIT_DEFAULT) — on an STA thread this pumps COM RPC
    // messages (delivered via the hidden COM window) while waiting on our
    // event, so re-entrant dispatch (e.g. a CancelOperation during a
    // MakeCredential) is not starved. In windows-rs 0.61 this returns the
    // signaled index as Result<u32>.
    let _idx = unsafe {
        CoWaitForMultipleHandles(0, INFINITE, &[event])
            .expect("CoWaitForMultipleHandles failed")
    };

    // Ordering invariant: the spawned task performs tx.send → SetEvent → task
    // returns. The STA wakes on SetEvent, then recv sees the already-sent
    // value. SetEvent is the last kernel-handle touch the worker makes, so
    // CloseHandle here is race-free with respect to the worker.
    let recv_result = rx.recv();
    unsafe {
        let _ = CloseHandle(event);
    }
    // Err here means the spawned task panicked. Propagate via panic on the
    // STA thread — the COM dispatch function's `catch_unwind` (if we ever add
    // one) would turn this into an HRESULT; for now, a panic is strictly
    // better than a silent hang.
    recv_result.expect("tokio task panicked — see logs")
}

/// CLSID of the PassKee plugin as a Guid struct. Declared `static` (not
/// `const`) so we can take its address — the options struct's `rclsid`
/// field is `REFCLSID` (a pointer-to-GUID), not an inline GUID.
#[cfg(windows)]
static CLSID_GUID: crate::com::types::Guid = crate::com::types::Guid {
    data1: 0xd26b_cf6f,
    data2: 0xb54c,
    data3: 0x43ff,
    data4: [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7],
};

/// Human-visible name shown in Settings → Accounts → Passkeys → Advanced.
#[cfg(windows)]
const AUTHENTICATOR_DISPLAY_NAME: &str = "PassKee";

/// Non-null `pwszPluginRpId` — the runtime API rejects null here even
/// though SDK docs mark the field "Optional, required for nested
/// WebAuthN calls". The Microsoft PasskeyManager reference sample always
/// sets a real domain string (`contoso.com`). Use a `.local` so it can
/// never be mistaken for a registered public suffix.
#[cfg(windows)]
const PLUGIN_RP_ID: &str = "passkee.local";

/// Minimal valid base64-encoded SVG 1.1 for the theme-logo fields.
/// The SDK header marks `pwszLightThemeLogo` / `pwszDarkThemeLogo` as
/// "Optional", but the Microsoft PasskeyManager reference sample always
/// passes non-null base64 SVG here — and the runtime rejects null with
/// an opaque `NTE_INVALID_PARAMETER`. Same logo for both themes is fine;
/// Phase 3 can bundle a proper PassKee brand icon.
///
/// Decodes to: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"/>`
#[cfg(windows)]
const THEME_LOGO_SVG_B64: &str =
    "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIvPg==";

// PASSKEE_AAGUID and authenticator_get_info_cbor() live in
// `crate::com::authenticator_info` — cross-platform so Linux CI covers the
// CBOR encoding. `cmd_register` imports them below.

/// Convert a Rust `&str` to a null-terminated UTF-16 buffer suitable for
/// passing as `LPCWSTR`. The returned `Vec<u16>` owns the data; the caller
/// must keep it alive until the FFI call returns.
#[cfg(windows)]
fn to_utf16_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// RAII guard that calls `CoUninitialize` on drop. Pairs with a preceding
/// `CoInitializeEx`. Ensures we balance the apartment init even if an
/// early-return / error occurs between init and the scope end.
#[cfg(windows)]
struct ComUninitGuard;

#[cfg(windows)]
impl Drop for ComUninitGuard {
    fn drop(&mut self) {
        unsafe { windows::Win32::System::Com::CoUninitialize() };
    }
}

/// Register PassKee as a passkey provider with Windows WebAuthn.
///
/// Calls `EXPERIMENTAL_WebAuthNPluginAddAuthenticator` with our CLSID, a
/// minimal `authenticatorGetInfo` CBOR blob, and null optional fields. On
/// S_OK the WebAuthN API returns an operation-signing public key inside a
/// heap-allocated response struct — we free it immediately via
/// `EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse`. The key is
/// intentionally discarded (signature-verification on incoming plugin
/// requests is a Phase 5 non-goal; see MEMORY.md).
///
/// Idempotence: Microsoft's docs claim re-register updates an existing
/// registration. Empirically on Win11 25H2 26200.8037 the API returns
/// `NTE_EXISTS` (0x8009_000F) instead. We emulate atomic-refresh: on
/// NTE_EXISTS, call `remove_authenticator` (best-effort) then retry Add
/// once. Any HRESULT other than S_OK or NTE_EXISTS is a hard error.
#[cfg(windows)]
pub fn cmd_register() -> Result<(), String> {
    use crate::com::authenticator_info::authenticator_get_info_cbor;
    use crate::com::types::WebauthnPluginAddAuthenticatorOptions;
    use crate::com::webauthn_ext;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

    // Initialise COM on this thread — the WebAuthN plugin API very likely
    // routes through COM internally to validate the CLSID registration
    // (devil's-advocate hypothesis #2). `main()` as invoked via
    // `passkee-provider.exe register` never calls CoInitializeEx otherwise.
    // S_FALSE (already initialised) is accepted; anything else is a hard
    // stop. ComUninitGuard ensures CoUninitialize runs on every exit path.
    let co_init_hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if co_init_hr.is_err() {
        return Err(format!("CoInitializeEx(STA) failed: 0x{:08x}", co_init_hr.0 as u32));
    }
    // Ensure CoUninitialize runs on every exit path.
    let _co_guard = ComUninitGuard;

    // Keep all owned data alive for the duration of the FFI call.
    let name_w  = to_utf16_null(AUTHENTICATOR_DISPLAY_NAME);
    let rp_id_w = to_utf16_null(PLUGIN_RP_ID);
    let logo_w  = to_utf16_null(THEME_LOGO_SVG_B64);
    let info    = authenticator_get_info_cbor();

    let opts = WebauthnPluginAddAuthenticatorOptions {
        pwsz_authenticator_name:   name_w.as_ptr(),
        rclsid:                    &CLSID_GUID as *const _,
        pwsz_plugin_rp_id:         rp_id_w.as_ptr(),
        pwsz_light_theme_logo_svg: logo_w.as_ptr(),
        pwsz_dark_theme_logo_svg:  logo_w.as_ptr(),
        cb_authenticator_info:     info.len() as u32,
        pb_authenticator_info:     info.as_ptr(),
        c_supported_rp_ids:        0,                    // 0 = support all RPs
        ppwsz_supported_rp_ids:    std::ptr::null(),
    };

    // ── Diagnostic dump ──────────────────────────────────────────────────
    // Prints the full state we're about to pass to webauthn.dll. Useful if
    // the struct is ever wrong again — previous iterations hit crashes
    // only visible via this trace. Keep until Phase 2.2 validation
    // succeeds end-to-end.
    let resolved_symbol = webauthn_ext::resolved_add_symbol_name().unwrap_or("<bindings not loaded>");
    eprintln!("[register] ==== diagnostic dump ====");
    eprintln!("[register] Resolved symbol: {resolved_symbol}");
    eprintln!("[register] Struct size:     {} bytes (expected 72)", std::mem::size_of::<WebauthnPluginAddAuthenticatorOptions>());
    eprintln!("[register] name_w   (LPCWSTR):  {:p} wchars={} \"{AUTHENTICATOR_DISPLAY_NAME}\"", name_w.as_ptr(), name_w.len());
    eprintln!("[register] rclsid   (REFCLSID): {:p} -> {{d26bcf6f-b54c-43ff-9f06-d5bf148625f7}}", &CLSID_GUID as *const _);
    eprintln!("[register] rp_id_w  (LPCWSTR):  {:p} wchars={} \"{PLUGIN_RP_ID}\"",               rp_id_w.as_ptr(), rp_id_w.len());
    eprintln!("[register] logo_w   (LPCWSTR):  {:p} wchars={} (shared light+dark, {}B base64 SVG)", logo_w.as_ptr(), logo_w.len(), THEME_LOGO_SVG_B64.len());
    eprintln!("[register] info     (PBYTE):    {:p} cbAuthenticatorInfo={}B", info.as_ptr(), info.len());
    eprintln!("[register] cSupportedRpIds=0 ppwszSupportedRpIds=NULL");
    eprintln!("[register] ==== calling ... ====");
    // Flush now — if we crash the buffered stderr may be lost.
    use std::io::Write;
    let _ = std::io::stderr().flush();

    // HRESULT the EXPERIMENTAL_ API returns when our CLSID is already
    // registered. Documented "re-register updates existing" semantics are
    // not implemented by the runtime — we must emulate via remove+retry.
    const HR_NTE_EXISTS: u32 = 0x8009_000F;

    let mut response_ptr: *mut crate::com::types::WebauthnPluginAddAuthenticatorResponse
        = std::ptr::null_mut();

    let hr = webauthn_ext::add_authenticator(&opts, &mut response_ptr)?;

    // Free the response BEFORE error-handling so the op-signing key is
    // never leaked, even on partial-success HRESULTs.
    // free_add_authenticator_response is a no-op on null.
    webauthn_ext::free_add_authenticator_response(response_ptr);

    if hr.0 as u32 == HR_NTE_EXISTS {
        eprintln!(
            "[register] NTE_EXISTS (0x8009000f) — stale registration present; removing and retrying Add."
        );

        // Best-effort unregister. If it fails (shouldn't), the retry will
        // surface the real error code.
        let _ = webauthn_ext::remove_authenticator(&CLSID_GUID as *const _);

        let mut retry_response_ptr: *mut crate::com::types::WebauthnPluginAddAuthenticatorResponse
            = std::ptr::null_mut();
        let hr_retry = webauthn_ext::add_authenticator(&opts, &mut retry_response_ptr)?;
        webauthn_ext::free_add_authenticator_response(retry_response_ptr);

        if hr_retry.is_err() {
            return Err(format!(
                "WebAuthNPluginAddAuthenticator failed after remove+retry: 0x{:08x}",
                hr_retry.0 as u32,
            ));
        }
        eprintln!("[register] remove+retry succeeded.");
    } else if hr.is_err() {
        return Err(format!(
            "WebAuthNPluginAddAuthenticator failed: 0x{:08x}",
            hr.0 as u32,
        ));
    }

    println!("PassKee registered as a passkey provider.");
    Ok(())
}

/// Unregister PassKee from Windows WebAuthn. Idempotent: if the plugin is
/// not currently registered, the API returns `HRESULT_FROM_WIN32(ERROR_NOT_FOUND)`
/// which we map to a warning + success.
#[cfg(windows)]
pub fn cmd_unregister() -> Result<(), String> {
    use crate::com::webauthn_ext;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};

    // Same rationale as cmd_register — initialise COM on this thread.
    let co_init_hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if co_init_hr.is_err() {
        return Err(format!("CoInitializeEx(STA) failed: 0x{:08x}", co_init_hr.0 as u32));
    }
    let _co_guard = ComUninitGuard;

    // Two HRESULTs encode the same semantic "no such registration":
    //   0x80070490 = HRESULT_FROM_WIN32(ERROR_NOT_FOUND       = 1168)
    //   0x80070002 = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND  = 2)
    // The EXPERIMENTAL_ API returns the latter in practice — observed on
    // build 26200.8037. Treat both as idempotent success.
    const HR_NOT_FOUND:      u32 = 0x8007_0490;
    const HR_FILE_NOT_FOUND: u32 = 0x8007_0002;

    let hr = webauthn_ext::remove_authenticator(&CLSID_GUID as *const _)?;

    match hr.0 as u32 {
        0 => {
            println!("PassKee unregistered.");
            Ok(())
        }
        HR_NOT_FOUND | HR_FILE_NOT_FOUND => {
            eprintln!("[unregister] not currently registered (0x{:08x}) — treating as success.", hr.0 as u32);
            Ok(())
        }
        code => Err(format!(
            "EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator failed: 0x{:08x}",
            code,
        )),
    }
}

