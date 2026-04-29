//! EXE-server entry points and ClassFactory for IPluginAuthenticator.
//!
//! The Windows WebAuthn host activates KeePassKeyWin via
//!   CoCreateInstance(CLSID_KeePassKeyWin, CLSCTX_LOCAL_SERVER, ...)
//! which causes the OS to launch `keepasskeywin-provider.exe -PluginActivated`.
//! The EXE then calls `run_com_server()` which registers the ClassFactory on
//! an STA and pumps messages until the last object is released.
//!
//! CLSID_KeePassKeyWin = {5c6840dc-8bed-4951-9576-b0457fc34e71}
//! (Distinct from IID_IPluginAuthenticator = {d26bcf6f-b54c-43ff-9f06-d5bf148625f7},
//! which is Microsoft's well-known interface ID — we implement that interface,
//! but our COM class has its own CLSID.)
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
        KeePassKeyWinAuthenticatorState,
    };

    // IID_IClassFactory = {00000001-0000-0000-C000-000000000046}
    const IID_ICLASS_FACTORY: GUID = GUID::from_u128(0x00000001_0000_0000_C000_000000000046);
    // IID_IUnknown = {00000000-0000-0000-C000-000000000046}
    const IID_IUNKNOWN: GUID = GUID::from_u128(0x00000000_0000_0000_C000_000000000046);
    // CLSID_KeePassKeyWin = {5c6840dc-8bed-4951-9576-b0457fc34e71}
    // (Distinct from IID_IPluginAuthenticator — see module-level doc.)
    pub(crate) const CLSID_KEEPASSKEYWIN: GUID = GUID::from_u128(0x5c6840dc_8bed_4951_9576_b0457fc34e71);

    /// Shared Tokio runtime. Populated by `run_com_server` before the class
    /// factory is registered; consumed by `cf_create_instance` and
    /// `sta_block_on`.
    pub static RT: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();

    /// Process-wide authenticator state shared across every `IPluginAuthenticator`
    /// instance handed out by `cf_create_instance`. The pipe + session_id are
    /// established once on the first activation; subsequent activations reuse.
    ///
    /// Why: webauthn.dll issues `CoCreateInstance` per operation (MakeCredential,
    /// then GetAssertion) without releasing the prior object promptly. The
    /// plugin-side `PipeServer` accepts exactly one concurrent client
    /// (`maxNumberOfServerInstances = 1`, see KeePassKeyWin.Core/Ipc/PipeServer.cs).
    /// A per-object pipe meant Object 2 hit `ERROR_PIPE_BUSY` while Object 1
    /// still held the only slot. Sharing the Arc lets the STA thread serialize
    /// dispatches through the inner Mutex over the one pipe.
    static SHARED_STATE: Mutex<Option<Arc<Mutex<KeePassKeyWinAuthenticatorState>>>> =
        Mutex::new(None);

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
        macro_rules! dbg_step { ($($arg:tt)*) => {
            tracing::info!("[activate] {}", format_args!($($arg)*))
        } }

        let session_id = unsafe { (*this).session_id };
        dbg_step!("cf_create_instance session_id={session_id}");

        // Reuse the process-wide state if already established (see SHARED_STATE
        // docs above for the pipe-busy rationale). First activation runs the
        // pipe connect + keepasskeywin.hello handshake; subsequent activations clone
        // the Arc so every COM object shares the single pipe.
        let state = {
            let guard = SHARED_STATE.lock().unwrap();
            guard.as_ref().map(Arc::clone)
        };

        let state = match state {
            Some(s) => {
                dbg_step!("reusing process-shared pipe state");
                s
            }
            None => {
                // Pull the shared runtime. Panic is intentional — only reachable
                // after run_com_server has populated RT.
                let runtime = RT.get().expect("runtime uninitialised").clone();

                // Connect the pipe AND complete the keepasskeywin.hello handshake
                // before handing the authenticator object to the caller. The
                // plugin-side RpcDispatcher rejects every non-`keepasskeywin.hello`
                // method until the per-connection ConnectionContext has
                // HandshakeComplete=true, so without this we can't dispatch
                // anything.
                //
                // Concurrency note: the HKCU nonce is read by THIS activation,
                // then consumed + rotated by the plugin on our handshake call.
                // If two browser registrations activate two sidecars
                // concurrently, both read the same nonce; the first handshake
                // wins, the second gets HandshakeInvalid and drops the pipe.
                // Not a v1 concern — browsers don't register concurrently.
                // Documented in docs/IPC_PROTOCOL.md.
                //
                // Implementation shares `connect_and_handshake` with the
                // 5.UV.8 inline stale-pipe retry path (server::take_call_with_retry)
                // — DRY between activation and retry, single failure mode
                // catalog, single set of breadcrumbs.
                let pipe = runtime.block_on(async {
                    connect_and_handshake(session_id, "[activate]").await.ok()
                });

                // Only cache in SHARED_STATE when the handshake actually
                // succeeded. A cached None would pin the process into a
                // permanent failure state if the first activation raced
                // against a not-yet-ready KeePass plugin.
                let fresh = Arc::new(Mutex::new(KeePassKeyWinAuthenticatorState {
                    session_id,
                    pipe,
                }));
                if fresh.lock().unwrap().pipe.is_some() {
                    *SHARED_STATE.lock().unwrap() = Some(fresh.clone());

                    // Best-effort startup reconciliation: sync vault credentials
                    // into the OS autofill database. Runs once per process on
                    // first successful activation. Uses the pipe briefly to call
                    // keepasskeywin.enumerateForSync, then returns it before any COM
                    // operation can arrive.
                    //
                    // Race window: the browser may call MakeCredential immediately
                    // after cf_create_instance returns. If reconciliation holds the
                    // pipe at that moment, MakeCredential sees pipe=None → E_FAIL.
                    // This is an accepted best-effort trade-off (startup sync, not
                    // a correctness requirement). The window is bounded by one
                    // enumerateForSync round-trip (~1–5 ms on a local pipe).
                    let state_for_reconcile = fresh.clone();
                    let rt = RT.get().expect("runtime uninitialised").clone();
                    rt.spawn(reconcile_vault_with_os(state_for_reconcile));
                }
                fresh
            }
        };

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
    /// `KeePassKeyWin.Core.Ipc.HandshakeHandler.ExpectedPkgFamily` on the C# side
    /// — the plugin rejects handshakes from any other PFN. If the package
    /// publisher identity ever changes this constant and the C# constant
    /// MUST be updated in lockstep.
    pub(crate) const KEEPASSKEYWIN_PKG_FAMILY: &str = "KeePassKeyWin.Provider_4fv17arhjxxvg";

    /// Read the current handshake nonce from
    /// `HKCU\Software\KeePassKeyWin\HandshakeNonce`. The plugin writes it on
    /// startup and rotates on each successful consume.
    ///
    /// Returns `Ok(nonce_string)` on success or a [`crate::com::reg_read_error::RegReadError`]
    /// variant that faithfully describes the failure reason so `connect_and_handshake`
    /// can emit a precise log message and error (5.UV.9). Uses `RRF_RT_ANY`
    /// (no built-in type filter) so the value-type out-param is populated even
    /// when `RegGetValueW` succeeds — enabling `WrongType` detection without a
    /// second registry call.
    pub(crate) fn read_handshake_nonce() -> Result<String, crate::com::reg_read_error::RegReadError> {
        use crate::com::reg_read_error::{lstatus_to_reg_read_error, RegReadError};
        use windows::core::PCWSTR;
        use windows::Win32::System::Registry::{
            RegGetValueW, HKEY_CURRENT_USER, RRF_RT_ANY, REG_VALUE_TYPE, REG_SZ,
        };

        let sub_key: Vec<u16>    = "Software\\KeePassKeyWin\0".encode_utf16().collect();
        let value_name: Vec<u16> = "HandshakeNonce\0".encode_utf16().collect();

        // Nonce is 64 hex chars + null = 130 bytes. 512 is plenty.
        let mut buf: [u16; 256] = [0u16; 256];
        let mut cb: u32 = (buf.len() * 2) as u32;
        // Capture the actual REG type so we can detect wrong-type on success.
        // Using RRF_RT_ANY (no built-in filter) ensures pdwType is populated
        // regardless of the actual type; we verify REG_SZ ourselves below.
        let mut actual_type = REG_VALUE_TYPE(0u32);

        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(sub_key.as_ptr()),
                PCWSTR(value_name.as_ptr()),
                RRF_RT_ANY,
                Some(&mut actual_type),
                Some(buf.as_mut_ptr() as *mut _),
                Some(&mut cb),
            )
        };

        if status.is_err() {
            // status.0 is the raw WIN32_ERROR u32; cast to i32 for the mapper.
            return Err(lstatus_to_reg_read_error(status.0 as i32, None));
        }

        // Read succeeded but we must verify the type ourselves (RRF_RT_ANY).
        if actual_type != REG_SZ {
            return Err(RegReadError::WrongType { actual_type: actual_type.0 });
        }

        // cb is bytes written including the trailing UTF-16 null.
        let wchars = (cb as usize) / 2;
        let end = buf[..wchars].iter().position(|&c| c == 0).unwrap_or(wchars);
        String::from_utf16(&buf[..end]).map_err(|_| RegReadError::Other(0))
    }

    /// Connect the plugin pipe and complete the `keepasskeywin.hello`
    /// handshake. Shared between first-activation (`cf_create_instance`) and
    /// the 5.UV.8 inline stale-pipe retry path (`server::take_call_with_retry`).
    ///
    /// Each step (pipe connect → nonce read → handshake) emits a tracing
    /// breadcrumb under the caller-supplied `log_prefix` so the unified
    /// failure-mode catalog reads naturally in `sidecar.log`. Production
    /// call sites currently pass `"[activate]"` (first-activation),
    /// `"[dispatch]"` (dispatch-time retry), `"[cancel]"` (cancel-time
    /// retry), and `"[lock-status]"` (getLockStatus-time retry); other
    /// `&'static str` prefixes are accepted. Tracing levels: `info!` for
    /// success and pipe-connect / nonce-read failures (which are
    /// "plugin-not-running-yet" signals during normal startup); `warn!` for
    /// handshake-protocol failure (PFN mismatch, plugin sig-verify reject,
    /// op-sign-key absence) — that's a *protocol* fault rather than a
    /// connectivity fault, so it deserves heightened visibility.
    ///
    /// The 5.UV.4 op-signing public-key requirement is enforced internally —
    /// `handshake()` returns `Err(InvalidRequest)` when the key is unavailable.
    ///
    /// `log_prefix` is `&'static str` rather than `&str` because the helper
    /// is called inside futures driven by `runtime.block_on` and `sta_block_on`,
    /// both of which require `'static` futures (the latter additionally
    /// requires `Send`). Production call sites pass string literals, so
    /// this constraint is invisible.
    pub(crate) async fn connect_and_handshake(
        session_id: u32,
        log_prefix: &'static str,
    ) -> Result<crate::ipc::PipeClient, crate::ipc::ClientError> {
        use crate::ipc::ClientError;

        let mut p = match crate::ipc::PipeClient::connect(session_id).await {
            Ok(p) => {
                tracing::info!("{log_prefix} pipe connect OK");
                p
            }
            Err(e) => {
                tracing::info!("{log_prefix} pipe connect FAILED: {e}");
                return Err(e);
            }
        };

        let nonce = match read_handshake_nonce() {
            Ok(n) => {
                let prefix: String = n.chars().take(8).collect();
                tracing::info!(
                    "{log_prefix} read nonce from HKCU: \"{prefix}...\" ({} chars)",
                    n.len()
                );
                n
            }
            Err(e) => {
                use crate::com::reg_read_error::RegReadError;
                // 5.UV.9: map each variant to a faithful message so the log
                // line and error string accurately describe the root cause.
                let reason = match &e {
                    RegReadError::NotFound =>
                        "HKCU\\Software\\KeePassKeyWin\\HandshakeNonce not found".to_string(),
                    RegReadError::WrongType { actual_type } =>
                        format!(
                            "HKCU\\Software\\KeePassKeyWin\\HandshakeNonce wrong value type \
                             0x{actual_type:x} (expected REG_SZ 0x1)"
                        ),
                    RegReadError::AccessDenied =>
                        "HKCU\\Software\\KeePassKeyWin\\HandshakeNonce access denied".to_string(),
                    RegReadError::BufferTooSmall =>
                        "HKCU\\Software\\KeePassKeyWin\\HandshakeNonce buffer too small".to_string(),
                    RegReadError::Other(code) =>
                        format!(
                            "HKCU\\Software\\KeePassKeyWin\\HandshakeNonce LSTATUS 0x{:08x}",
                            *code as u32
                        ),
                };
                tracing::info!("{log_prefix} read nonce FAILED — {reason}");
                return Err(ClientError::InvalidRequest(reason));
            }
        };

        // 5.UV.4: opSignPublicKeyB64 is required by the plugin. Fetch the key
        // bytes before sending hello; if unavailable, handshake() returns
        // Err(InvalidRequest) and we propagate it.
        let pub_key = crate::com::request_sig::get_op_sign_pub_key_bytes_for_hello();
        match p.handshake(KEEPASSKEYWIN_PKG_FAMILY, &nonce, pub_key).await {
            Ok(()) => {
                tracing::info!("{log_prefix} handshake OK");
                Ok(p)
            }
            Err(e) => {
                // `warn!` (not `info!`) — handshake failure with a fresh
                // pipe signals a *protocol* fault: PFN mismatch, plugin
                // sig-verify rejection, or op-sign-key absence. Distinct
                // from connect/nonce failures, which are normal-startup
                // "plugin not ready yet" signals at `info!`.
                tracing::warn!("{log_prefix} handshake FAILED: {e:?}");
                Err(e)
            }
        }
    }

    /// Clear the process-wide `SHARED_STATE` slot. Called from the 5.UV.8
    /// retry helper (`server::take_call_with_retry`) when reconnect+rehandshake
    /// fails on a retry — without this, the next COM activation would reuse
    /// a half-dead `Arc` whose inner pipe is permanently `None` (the
    /// unconditional `.take()` at the entry of `take_call_with_retry`
    /// happens *before* the retry decision is made, so the surviving Arc
    /// has `pipe = None` regardless of retry outcome).
    ///
    /// Race-safety: in-flight dispatches hold their own `Arc` clones; this
    /// function only drops the slot's clone. `strong_count` does not reach
    /// zero just because this slot is cleared. Goes through the generic
    /// `classify_rpc_error::clear_slot` so the underlying logic is exercised
    /// by Linux-CI unit tests with a stub `T`.
    pub(crate) fn clear_shared_state() {
        crate::com::classify_rpc_error::clear_slot(&SHARED_STATE);
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

    // ── Startup vault↔OS reconciliation ─────────────────────────────────────

    /// Best-effort background task: sync vault credentials into the OS
    /// autofill database on first activation.
    ///
    /// Flow:
    ///   1. Take the pipe from state briefly, call `keepasskeywin.enumerateForSync`,
    ///      return the pipe.
    ///   2. Call `GetAllCredentials` (sync FFI) to get what the OS knows.
    ///   3. For vault creds missing from OS: call `AddCredentials`.
    ///   4. For OS creds missing from vault: call `RemoveCredentials`.
    ///   5. Call `FreeCredentialDetailsArray`.
    ///
    /// Never panics, never blocks COM activation. All failures are logged at
    /// debug level with the `[reconcile]` breadcrumb.
    async fn reconcile_vault_with_os(
        state: Arc<Mutex<KeePassKeyWinAuthenticatorState>>,
    ) {
        use base64::Engine;
        use crate::com::server::parse_add_credentials_fields;
        use crate::com::types::WebauthnPluginCredentialDetails;
        use crate::com::webauthnplugin_ext;
        use crate::ipc::ClientError;

        macro_rules! dbg { ($($arg:tt)*) => {
            tracing::debug!("[reconcile] {}", format_args!($($arg)*))
        } }

        dbg!("start");

        // ── Step 1: enumerate vault credentials via IPC ───────────────────────
        let pipe_opt = { state.lock().unwrap().pipe.take() };
        let mut pipe = match pipe_opt {
            Some(p) => p,
            None => {
                dbg!("pipe unavailable — skipping");
                return;
            }
        };

        let (rpc_result, pipe_back): (Result<serde_json::Value, ClientError>, _) = {
            let r = pipe.call("keepasskeywin.enumerateForSync", serde_json::json!({})).await;
            (r, pipe)
        };
        state.lock().unwrap().pipe = Some(pipe_back);

        let vault_arr = match rpc_result {
            Ok(v) => match v.as_array().cloned() {
                Some(a) => a,
                None => {
                    dbg!("enumerateForSync returned non-array — skipping");
                    return;
                }
            },
            Err(e) => {
                dbg!("enumerateForSync failed: {e:?} — skipping");
                return;
            }
        };
        dbg!("vault has {} credential(s)", vault_arr.len());

        // ── Step 2: get OS credential list ────────────────────────────────────
        let rclsid_ptr = &crate::com::exe_server::CLSID_GUID as *const _;
        let (os_count, os_arr_ptr) = match webauthnplugin_ext::get_all_credentials(rclsid_ptr) {
            Ok(pair) => pair,
            Err(e) => {
                dbg!("GetAllCredentials failed: {e} — skipping");
                return;
            }
        };
        dbg!("OS has {os_count} credential(s)");

        // Collect OS credential IDs (raw bytes) for the comparison.
        // SAFETY: os_arr_ptr is valid for os_count elements until FreeCredentialDetailsArray.
        let os_ids: Vec<Vec<u8>> = if os_count > 0 && !os_arr_ptr.is_null() {
            (0..os_count as usize).map(|i| {
                let detail = unsafe { &*os_arr_ptr.add(i) };
                if detail.pb_credential_id.is_null() || detail.cb_credential_id == 0 {
                    Vec::new()
                } else {
                    unsafe {
                        std::slice::from_raw_parts(
                            detail.pb_credential_id,
                            detail.cb_credential_id as usize,
                        )
                    }.to_vec()
                }
            }).collect()
        } else {
            Vec::new()
        };

        // ── Step 3: add vault creds missing from OS ───────────────────────────
        //
        // The enumerateForSync response uses field names `credentialId` and
        // `userHandle` (plain base64url strings, no `B64Url` suffix) whereas
        // parse_add_credentials_fields reads `credentialIdB64Url` /
        // `userHandleB64Url`. Translate the field names before reusing it.
        let mut added = 0u32;
        let mut skipped_parse = 0u32;

        for item in &vault_arr {
            let cred_id_b64 = match item["credentialId"].as_str() {
                Some(s) => s,
                None => { skipped_parse += 1; continue; }
            };
            let cred_id_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(cred_id_b64)
            {
                Ok(b) => b,
                Err(_) => { skipped_parse += 1; continue; }
            };

            if os_ids.contains(&cred_id_bytes) {
                continue; // already known to OS
            }

            // Translate field names for parse_add_credentials_fields.
            let translated = serde_json::json!({
                "credentialIdB64Url": item["credentialId"],
                "rpId":               item["rpId"],
                "rpName":             item["rpName"],
                "userHandleB64Url":   item["userHandle"],
                "userName":           item["userName"],
                "userDisplayName":    item["userDisplayName"],
            });

            let fields = match parse_add_credentials_fields(&translated) {
                Ok(f) => f,
                Err(field) => {
                    dbg!("skip add: parse error on field {field}");
                    skipped_parse += 1;
                    continue;
                }
            };

            let detail = WebauthnPluginCredentialDetails {
                cb_credential_id:       fields.credential_id.len() as u32,
                pb_credential_id:       fields.credential_id.as_ptr(),
                pwsz_rp_id:             fields.rp_id_w.as_ptr(),
                pwsz_rp_name:           fields.rp_name_w.as_ptr(),
                cb_user_id:             fields.user_handle.len() as u32,
                pb_user_id:             fields.user_handle.as_ptr(),
                pwsz_user_name:         fields.user_name_w.as_ptr(),
                pwsz_user_display_name: fields.user_disp_w.as_ptr(),
            };

            match webauthnplugin_ext::add_credentials(rclsid_ptr, std::slice::from_ref(&detail)) {
                Ok(hr) => {
                    dbg!("AddCredentials hr=0x{:08x} for credId prefix={}", hr.0 as u32,
                         &cred_id_b64[..cred_id_b64.len().min(8)]);
                    if hr.0 == 0 { added += 1; }
                }
                Err(e) => {
                    dbg!("AddCredentials FFI unavailable: {e}");
                    // If FFI is completely unavailable, abort — all subsequent
                    // calls will fail the same way.
                    if os_count > 0 && !os_arr_ptr.is_null() {
                        webauthnplugin_ext::free_credential_details_array(os_count, os_arr_ptr);
                    }
                    return;
                }
            }
            drop(fields);
        }

        // ── Step 4: remove OS creds missing from vault ────────────────────────
        let mut removed = 0u32;
        if os_count > 0 && !os_arr_ptr.is_null() {
            let vault_ids: Vec<Vec<u8>> = vault_arr.iter().filter_map(|item| {
                let s = item["credentialId"].as_str()?;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
            }).collect();

            for (i, os_id) in os_ids.iter().enumerate() {
                if os_id.is_empty() { continue; }
                if vault_ids.contains(os_id) {
                    continue; // still in vault
                }

                // SAFETY: os_arr_ptr.add(i) is valid until FreeCredentialDetailsArray.
                let detail_ptr = unsafe { os_arr_ptr.add(i) as *const _ };
                match webauthnplugin_ext::remove_credentials(rclsid_ptr, detail_ptr) {
                    Ok(hr) => {
                        dbg!("RemoveCredentials hr=0x{:08x}", hr.0 as u32);
                        if hr.0 == 0 { removed += 1; }
                    }
                    Err(e) => {
                        dbg!("RemoveCredentials FFI unavailable: {e}");
                        break;
                    }
                }
            }
        }

        // ── Step 5: free the OS array ─────────────────────────────────────────
        if os_count > 0 && !os_arr_ptr.is_null() {
            webauthnplugin_ext::free_credential_details_array(os_count, os_arr_ptr);
        }

        dbg!("done — added={added} removed={removed} skipped_parse={skipped_parse}");
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

// 5.UV.8: shared connect+handshake helper and SHARED_STATE clearer, used by
// `com::server::take_call_with_retry`. Re-exported at module level so the
// retry path doesn't need to reach into `imp`.
#[cfg(windows)]
pub(crate) use imp::{clear_shared_state, connect_and_handshake};

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
            &imp::CLSID_KEEPASSKEYWIN,
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

/// CLSID of the KeePassKeyWin plugin as a Guid struct. Declared `static` (not
/// `const`) so we can take its address — the options struct's `rclsid`
/// field is `REFCLSID` (a pointer-to-GUID), not an inline GUID.
///
/// Also reused by `com::server::dispatch_operation` (via
/// `&CLSID_GUID as *const _`) when calling `WebAuthNPluginAuthenticator
/// AddCredentials` after a successful MakeCredential — same `REFCLSID`
/// pointer-not-inline convention.
#[cfg(windows)]
pub(crate) static CLSID_GUID: crate::com::types::Guid = crate::com::types::Guid {
    data1: 0x5c68_40dc,
    data2: 0x8bed,
    data3: 0x4951,
    data4: [0x95, 0x76, 0xb0, 0x45, 0x7f, 0xc3, 0x4e, 0x71],
};

/// Human-visible name shown in Settings → Accounts → Passkeys → Advanced.
#[cfg(windows)]
const AUTHENTICATOR_DISPLAY_NAME: &str = "KeePassKeyWin";

/// Non-null `pwszPluginRpId` — the runtime API rejects null here even
/// though SDK docs mark the field "Optional, required for nested
/// WebAuthN calls". The Microsoft PasskeyManager reference sample always
/// sets a real domain string (`contoso.com`). Use a `.local` so it can
/// never be mistaken for a registered public suffix.
#[cfg(windows)]
const PLUGIN_RP_ID: &str = "keepasskeywin.local";

/// Minimal valid base64-encoded SVG 1.1 for the theme-logo fields.
/// The SDK header marks `pwszLightThemeLogo` / `pwszDarkThemeLogo` as
/// "Optional", but the Microsoft PasskeyManager reference sample always
/// passes non-null base64 SVG here — and the runtime rejects null with
/// an opaque `NTE_INVALID_PARAMETER`. Same logo for both themes is fine;
/// Phase 3 can bundle a proper KeePassKeyWin brand icon.
///
/// Decodes to: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"/>`
#[cfg(windows)]
const THEME_LOGO_SVG_B64: &str =
    "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIvPg==";

// KEEPASSKEYWIN_AAGUID and authenticator_get_info_cbor() live in
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

/// Register KeePassKeyWin as a passkey provider with Windows WebAuthn.
///
/// Calls `EXPERIMENTAL_WebAuthNPluginAddAuthenticator` with our CLSID, a
/// minimal `authenticatorGetInfo` CBOR blob, and null optional fields. On
/// S_OK the WebAuthN API returns an operation-signing public key inside a
/// heap-allocated response struct — we free it immediately via
/// `EXPERIMENTAL_WebAuthNPluginFreeAddAuthenticatorResponse`. The key is
/// intentionally discarded (signature-verification on incoming plugin
/// requests is a Phase 5 non-goal; see docs/PLAN.md).
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
    // `keepasskeywin-provider.exe register` never calls CoInitializeEx otherwise.
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

    // Dump the full state we're about to pass to webauthn.dll (KEEPASSKEYWIN_LOG_LEVEL=debug to see).
    let resolved_symbol = webauthn_ext::resolved_add_symbol_name().unwrap_or("<bindings not loaded>");
    tracing::debug!("[register] ==== diagnostic dump ====");
    tracing::debug!("[register] Resolved symbol: {resolved_symbol}");
    tracing::debug!("[register] Struct size:     {} bytes (expected 72)", std::mem::size_of::<WebauthnPluginAddAuthenticatorOptions>());
    tracing::debug!("[register] name_w   (LPCWSTR):  {:p} wchars={} \"{AUTHENTICATOR_DISPLAY_NAME}\"", name_w.as_ptr(), name_w.len());
    tracing::debug!("[register] rclsid   (REFCLSID): {:p} -> {{5c6840dc-8bed-4951-9576-b0457fc34e71}}", &CLSID_GUID as *const _);
    tracing::debug!("[register] rp_id_w  (LPCWSTR):  {:p} wchars={} \"{PLUGIN_RP_ID}\"",               rp_id_w.as_ptr(), rp_id_w.len());
    tracing::debug!("[register] logo_w   (LPCWSTR):  {:p} wchars={} (shared light+dark, {}B base64 SVG)", logo_w.as_ptr(), logo_w.len(), THEME_LOGO_SVG_B64.len());
    tracing::debug!("[register] info     (PBYTE):    {:p} cbAuthenticatorInfo={}B", info.as_ptr(), info.len());
    tracing::debug!("[register] cSupportedRpIds=0 ppwszSupportedRpIds=NULL");
    tracing::debug!("[register] ==== calling ... ====");

    // HRESULT the EXPERIMENTAL_ API returns when our CLSID is already
    // registered. Documented "re-register updates existing" semantics are
    // not implemented by the runtime — we must emulate via remove+retry.
    const HR_NTE_EXISTS: u32 = 0x8009_000F;

    let mut response_ptr: *mut crate::com::types::WebauthnPluginAddAuthenticatorResponse
        = std::ptr::null_mut();

    // SAFETY: response_ptr is initialized to null_mut() above; Windows writes
    // the response pointer on S_OK. We free it immediately after via
    // free_add_authenticator_response (which is a no-op on null).
    let hr = unsafe { webauthn_ext::add_authenticator(&opts, &mut response_ptr) }?;

    // Free the response BEFORE error-handling so the op-signing key is
    // never leaked, even on partial-success HRESULTs.
    // free_add_authenticator_response is a no-op on null.
    // SAFETY: response_ptr is either null or the pointer written by add_authenticator.
    unsafe { webauthn_ext::free_add_authenticator_response(response_ptr) };

    if hr.0 as u32 == HR_NTE_EXISTS {
        tracing::info!(
            "[register] NTE_EXISTS (0x8009000f) — stale registration present; removing and retrying Add."
        );

        // Best-effort unregister. If it fails (shouldn't), the retry will
        // surface the real error code.
        // SAFETY: &CLSID_GUID is a valid non-null pointer to the registered CLSID.
        let _ = unsafe { webauthn_ext::remove_authenticator(&CLSID_GUID as *const _) };

        let mut retry_response_ptr: *mut crate::com::types::WebauthnPluginAddAuthenticatorResponse
            = std::ptr::null_mut();
        // SAFETY: retry_response_ptr initialized to null_mut(); freed immediately below.
        let hr_retry = unsafe { webauthn_ext::add_authenticator(&opts, &mut retry_response_ptr) }?;
        // SAFETY: retry_response_ptr is either null or the pointer written by add_authenticator.
        unsafe { webauthn_ext::free_add_authenticator_response(retry_response_ptr) };

        if hr_retry.is_err() {
            return Err(format!(
                "WebAuthNPluginAddAuthenticator failed after remove+retry: 0x{:08x}",
                hr_retry.0 as u32,
            ));
        }
        tracing::info!("[register] remove+retry succeeded.");
    } else if hr.is_err() {
        return Err(format!(
            "WebAuthNPluginAddAuthenticator failed: 0x{:08x}",
            hr.0 as u32,
        ));
    }

    println!("KeePassKeyWin registered as a passkey provider.");
    Ok(())
}

/// Unregister KeePassKeyWin from Windows WebAuthn. Idempotent: if the plugin is
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

    // SAFETY: &CLSID_GUID is a valid non-null pointer to our registered CLSID.
    let hr = unsafe { webauthn_ext::remove_authenticator(&CLSID_GUID as *const _) }?;

    match hr.0 as u32 {
        0 => {
            println!("KeePassKeyWin unregistered.");
            Ok(())
        }
        HR_NOT_FOUND | HR_FILE_NOT_FOUND => {
            tracing::info!("[unregister] not currently registered (0x{:08x}) — treating as success.", hr.0 as u32);
            Ok(())
        }
        code => Err(format!(
            "EXPERIMENTAL_WebAuthNPluginRemoveAuthenticator failed: 0x{:08x}",
            code,
        )),
    }
}

