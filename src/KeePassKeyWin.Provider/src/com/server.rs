//! KeePassKeyWinAuthenticator COM server — implements IPluginAuthenticator.
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

// ── Cross-platform helpers (must live outside the #[cfg(windows)] `imp`) ──
//
// These are called by the Windows-only `dispatch_operation` but are kept
// here — not gated — so Linux CI can test their parsing logic without
// needing to cross-compile the COM server itself. Same pattern as
// `extract_prompt_hint` (declared inside `imp` with `pub(crate)` and tested
// from a cross-platform module at the bottom of this file).

/// Owned byte / wide-string buffers extracted from a successful
/// `keepasskeywin.makeCredentialRaw` JSON-RPC response, kept alive by the
/// caller across the FFI call to `WebAuthNPluginAuthenticatorAddCredentials`.
///
/// Each `Vec<u16>` is null-terminated — suitable for direct use as
/// `LPCWSTR`. Byte slices (`credential_id`, `user_handle`) are raw,
/// unterminated, with length carried alongside in the FFI struct's
/// `cb_*` fields.
#[cfg(windows)]
pub(crate) struct AddCredentialsFields {
    pub credential_id: Vec<u8>,
    pub user_handle:   Vec<u8>,
    pub rp_id_w:       Vec<u16>,
    pub rp_name_w:     Vec<u16>,
    pub user_name_w:   Vec<u16>,
    pub user_disp_w:   Vec<u16>,
}

/// Parse the six post-Phase-3 credential-detail fields out of the JSON-RPC
/// response for `keepasskeywin.makeCredentialRaw`.
///
/// Returns `Err(&'static str)` naming the missing or malformed field so
/// the caller can emit `[addcreds] skip: response missing field X` to
/// stderr. Empty strings are materialised as a non-null null-terminator-
/// only buffer (see `encode_utf16_nul`) — Microsoft's
/// `PluginCredentialManager.cpp` validator treats null as invalid but
/// accepts non-null empty strings.
///
/// Encoding: `credentialIdB64Url` and `userHandleB64Url` are base64url
/// without padding (matches how the C# plugin stores both fields inside
/// a PwEntry). Mixed with the Phase-3 legacy `cbor` field which remains
/// base64-standard-with-padding — do not confuse the two decoders.
#[cfg(windows)]
pub(crate) fn parse_add_credentials_fields(
    v: &serde_json::Value,
) -> Result<AddCredentialsFields, &'static str> {
    use base64::Engine;

    let credential_id_b64 = v["credentialIdB64Url"].as_str().ok_or("credentialIdB64Url")?;
    let rp_id             = v["rpId"]              .as_str().ok_or("rpId")?;
    let rp_name           = v["rpName"]            .as_str().ok_or("rpName")?;
    let user_handle_b64   = v["userHandleB64Url"]  .as_str().ok_or("userHandleB64Url")?;
    let user_name         = v["userName"]          .as_str().ok_or("userName")?;
    let user_disp         = v["userDisplayName"]   .as_str().ok_or("userDisplayName")?;

    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(credential_id_b64)
        .map_err(|_| "credentialIdB64Url decode")?;
    let user_handle = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(user_handle_b64)
        .map_err(|_| "userHandleB64Url decode")?;

    Ok(AddCredentialsFields {
        credential_id,
        user_handle,
        rp_id_w:     encode_utf16_nul(rp_id),
        rp_name_w:   encode_utf16_nul(rp_name),
        user_name_w: encode_utf16_nul(user_name),
        user_disp_w: encode_utf16_nul(user_disp),
    })
}

/// UTF-16 encode `s` with a trailing null terminator. For empty strings
/// the returned `Vec<u16>` is `[0]` — a single null wide char, so
/// `as_ptr()` yields a valid, non-null `LPCWSTR` that dereferences to 0.
/// Microsoft's `PluginCredentialManager.cpp:235-238` validates non-null
/// but does not reject zero-length wide strings.
#[cfg(windows)]
fn encode_utf16_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

#[cfg(windows)]
pub(crate) mod imp {
    use std::sync::{Arc, Mutex};

    use windows::core::{GUID, HRESULT};
    use windows::Win32::System::Com::{CoReleaseServerProcess, CoTaskMemAlloc};

    use crate::com::exe_server::sta_block_on;
    use sha2::Digest as _;

    use crate::com::types::{
        PluginLockStatus, WebauthNPluginCancelOperationRequest,
        WebauthNPluginOperationRequest, WebauthNPluginOperationResponse,
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
    pub struct KeePassKeyWinAuthenticatorState {
        #[allow(dead_code)]
        pub session_id: u32,
        pub pipe: Option<PipeClient>,
    }

    #[repr(C)]
    pub struct IPluginAuthenticatorImpl {
        pub vtbl: *const IPluginAuthenticatorVtbl,
        pub ref_count: std::sync::atomic::AtomicU32,
        pub state: Arc<Mutex<KeePassKeyWinAuthenticatorState>>,
    }

    impl IPluginAuthenticatorImpl {
        pub fn new(state: Arc<Mutex<KeePassKeyWinAuthenticatorState>>) -> Box<Self> {
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

    // ── 5.UV.8 inline stale-pipe retry helper ────────────────────────────────

    /// Take the pipe out of `state`, perform the JSON-RPC call, and on a
    /// stale-pipe error (`RpcErrorClass::Stale`) drop the dead pipe,
    /// reconnect + re-handshake via `exe_server::connect_and_handshake`, and
    /// retry the call once with the same params. Reconciles `state.pipe`
    /// and `SHARED_STATE` internally — callers do nothing post-call beyond
    /// reading the returned `Option<Result>`.
    ///
    /// State reconciliation (handled internally so the load-bearing
    /// "pipe = None on ClearSharedState" invariant is type-enforced rather
    /// than convention-enforced):
    ///
    /// * First-attempt success / non-stale Err — original `pipe` is alive;
    ///   stored back into `state.pipe`.
    /// * Stale, retry-RPC succeeded / failed for non-connect reason — the
    ///   fresh pipe is alive (handshake completed); stored into `state.pipe`,
    ///   replacing the dead one.
    /// * Stale, retry's reconnect or re-handshake failed — `state.pipe` is
    ///   left as `None` (the entry-side `take()` already nulled it) and
    ///   `clear_shared_state()` is called so the next COM activation
    ///   reconnects from scratch instead of reusing this half-dead Arc.
    ///
    /// Returns:
    /// * `None` — `state.pipe` was already `None` at entry. Caller maps to
    ///   the method-specific default (E_FAIL for dispatch, S_OK for cancel,
    ///   `Locked` for getLockStatus).
    /// * `Some(Ok(value))` — first attempt or retry succeeded.
    /// * `Some(Err(e))` — first attempt failed for a non-stale reason
    ///   (vault locked, no credentials, etc.), OR retry's RPC failed, OR
    ///   retry's reconnect/handshake failed. Caller maps to its
    ///   method-specific HRESULT via the existing `match` arms.
    ///
    /// Exactly one retry per dispatch — no recursion. If the retry's RPC
    /// also produces a stale error, it propagates as a normal `Err` without
    /// a second retry. Tracing levels: `info!` for neutral breadcrumbs;
    /// `warn!` for the recoverable stale signal and retry-RPC errors;
    /// `error!` for retry-connect/handshake exhaustion.
    pub(crate) fn take_call_with_retry(
        state: &Arc<Mutex<KeePassKeyWinAuthenticatorState>>,
        method: &str,
        params: serde_json::Value,
        log_prefix: &'static str,
    ) -> Option<Result<serde_json::Value, ClientError>> {
        use crate::com::classify_rpc_error::{classify_rpc_error, RpcErrorClass};

        // Sync extract of pipe + session_id. The inner Mutex is released
        // before any `.await` — never held across STA-pumping waits (doing
        // so would deadlock a re-entrant COM dispatch on the same STA
        // thread; same rationale as `KeePassKeyWinAuthenticatorState`'s
        // doc above).
        let pipe = { state.lock().unwrap().pipe.take() }?;
        let session_id = { state.lock().unwrap().session_id };

        let method_owned = method.to_string();
        // Clone before move-into-future: the first `.call` consumes
        // `params`; the retry needs a fresh copy if r1 is Stale.
        let params_for_retry = params.clone();

        // Run the retry orchestration in a single STA-safe future. The
        // tuple's second element is `Option<PipeClient>`:
        //   Some(p) → store p back into state.pipe (first-attempt or retry
        //             produced a live pipe).
        //   None    → leave state.pipe = None and clear SHARED_STATE
        //             (retry's reconnect/handshake failed).
        let (result, fresh_pipe_opt): (Result<serde_json::Value, ClientError>, Option<PipeClient>) =
            sta_block_on(async move {
                let mut p = pipe;
                let r1 = p.call(&method_owned, params).await;

                // Borrow-only stale check; r1 is consumed below. The
                // matches! arm guarantees r1 is Err on the truthy branch —
                // any future refactor that changes this is a correctness
                // bug, see the unreachable! below.
                let is_stale = matches!(
                    &r1,
                    Err(e) if classify_rpc_error(e) == RpcErrorClass::Stale
                );
                if !is_stale {
                    return (r1, Some(p));
                }

                let stale_err = match r1 {
                    Err(e) => e,
                    Ok(_) => unreachable!(
                        "is_stale matches! above only fires on Err(_); refactor must preserve that invariant"
                    ),
                };
                tracing::warn!(
                    "{log_prefix} RPC err: {stale_err:?} — stale pipe, retrying once via reconnect+rehandshake"
                );
                drop(p);

                match crate::com::exe_server::connect_and_handshake(session_id, log_prefix).await {
                    Ok(mut fresh) => {
                        let r2 = fresh.call(&method_owned, params_for_retry).await;
                        match &r2 {
                            Ok(_) => tracing::info!("{log_prefix} retry OK"),
                            Err(e2) => tracing::warn!("{log_prefix} retry RPC err: {e2:?}"),
                        }
                        (r2, Some(fresh))
                    }
                    Err(connect_err) => {
                        tracing::error!(
                            "{log_prefix} retry connect/handshake failed: {connect_err:?} — clearing SHARED_STATE"
                        );
                        (Err(connect_err), None)
                    }
                }
            });

        // Reconcile state in exactly one place. `Some` ⇒ store the live pipe
        // back; `None` ⇒ leave state.pipe as None (already nulled by the
        // `take()` above) and clear SHARED_STATE so the next COM activation
        // reconnects from scratch instead of reusing this half-dead Arc.
        match fresh_pipe_opt {
            Some(p) => {
                state.lock().unwrap().pipe = Some(p);
            }
            None => {
                crate::com::exe_server::clear_shared_state();
            }
        }

        Some(result)
    }

    // ── IPluginAuthenticator ─────────────────────────────────────────────────

    unsafe extern "system" fn make_credential(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginOperationRequest,
        response: *mut WebauthNPluginOperationResponse,
    ) -> HRESULT {
        unsafe { dispatch_operation(this, request, response, "keepasskeywin.makeCredentialRaw") }
    }

    unsafe extern "system" fn get_assertion(
        this: *mut IPluginAuthenticatorImpl,
        request: *const WebauthNPluginOperationRequest,
        response: *mut WebauthNPluginOperationResponse,
    ) -> HRESULT {
        unsafe { dispatch_operation(this, request, response, "keepasskeywin.getAssertionRaw") }
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

        // cancel_operation forwards no pbRequestSignature to the plugin — cancel
        // is a best-effort abort signal with no vault side-effects, matching the
        // Microsoft PasskeyManager sample (PluginAuthenticatorImpl.cpp) which also
        // skips signature verification on CancelOperation. Plugin-side sig
        // verification (5.UV.2/5.UV.5) covers MakeCredential and GetAssertion only.

        // 5.UV.8: route through take_call_with_retry so a stale pipe
        // self-heals on cancel rather than poisoning the cached pipe for
        // the next real dispatch. The result is intentionally discarded —
        // cancel is a best-effort signal — but the helper's internal state
        // reconciliation (store-back vs clear SHARED_STATE) still matters.
        // None at entry = pipe already in use by another dispatch
        // (re-entrant case) or not connected; cancel reports S_OK either way.
        let params = serde_json::json!({ "transactionId": txn });
        let _ = take_call_with_retry(
            &obj.state,
            "keepasskeywin.cancelOperation",
            params,
            "[cancel]",
        );
        HRESULT(0)
    }

    unsafe extern "system" fn get_lock_status(
        this: *mut IPluginAuthenticatorImpl,
        lock_status: *mut PluginLockStatus,
    ) -> HRESULT {
        let obj = unsafe { &*this };

        // 5.UV.8: route through take_call_with_retry so a stale pipe
        // self-heals here (was a one-strike E_FAIL → "authenticator
        // unavailable" UX glitch in the Windows host before this fix; same
        // UX axis on which v1 was rejected for the dispatch path).
        let result = match take_call_with_retry(
            &obj.state,
            "keepasskeywin.getLockStatus",
            serde_json::json!({}),
            "[lock-status]",
        ) {
            Some(r) => r,
            None => {
                unsafe { *lock_status = PluginLockStatus::Locked };
                return HRESULT(0);
            }
        };

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
        // info-level: these are infrequent per-dispatch breadcrumbs (one per
        // operation) needed for any "why did the sidecar die at step N?" investigation.
        // The extract_prompt_hint line below is logged at debug! (not via this
        // macro) because the username string can contain RP-supplied PII
        // (display name, email-shaped handles); we want it gated behind
        // KEEPASSKEYWIN_LOG_LEVEL=debug so an admin enabling file logging on a shared/kiosk
        // machine doesn't capture authenticating-user identifiers by default.
        macro_rules! dbg_step { ($($arg:tt)*) => {
            tracing::info!("[dispatch] {}", format_args!($($arg)*))
        } }

        let obj = unsafe { &*this };
        let req = unsafe { &*request };
        let cbor_bytes = unsafe { req.encoded_request() };
        let cbor_b64 = base64::engine::general_purpose::STANDARD.encode(cbor_bytes);

        dbg_step!("ENTRY method={method} cbor_len={} request_type={:?} cb_sig={}",
                  cbor_bytes.len(), req.request_type, req.cb_request_signature);

        // ── Step 1: extract UV prompt hint from CBOR ──────────────────────────
        // PII gate: username_hint comes from the RP's userEntity.name (often an
        // email or handle). Logged at debug-level only, not the info-level
        // dbg_step! macro — see the macro definition above for rationale.
        let username_hint = extract_prompt_hint(cbor_bytes, method);
        tracing::debug!("[dispatch] extract_prompt_hint -> \"{username_hint}\"");

        // Forward sig bytes to the plugin for plugin-side verification (5.UV.2/5.UV.5).
        // Trade-off note: the pre-5.UV.5 sidecar gate verified pbRequestSignature
        // before perform_user_verification, so a forged request was rejected
        // before any UV prompt could fire. Post-5.UV.5, sig verification happens
        // plugin-side after the UV call (see ARCHITECTURE.md § "Trust boundary"
        // — Gate 1's accepted trade-off block). The vault is still unreachable;
        // the residual exposure is "spurious Hello prompt on forged request",
        // which requires local code exec to trigger.
        let sig_bytes: &[u8] = if req.cb_request_signature > 0 && !req.pb_request_signature.is_null() {
            unsafe { std::slice::from_raw_parts(req.pb_request_signature, req.cb_request_signature as usize) }
        } else {
            &[]
        };
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);

        // UTF-16 owned buffers — kept alive across the UV call.
        let username_w: Vec<u16> = username_hint.encode_utf16().chain(std::iter::once(0)).collect();
        let display_hint_w: Vec<u16> = "KeePassKeyWin\0".encode_utf16().collect();

        // ── Step 2: call PerformUserVerification(2) (inline on STA thread) ────
        //
        // 5.UV.3: compute SHA-256(pbEncodedRequest) once and pass it to the v2
        // entrypoint as `buffer_to_sign`. The Windows runtime signs this digest
        // and returns the opaque UV signature so the plugin can verify it
        // independently (Phase 5.UV.4). The digest is bound to a named variable
        // so it stays live through the FFI call — do NOT inline into the args.
        // Reuses the `sha2` crate already present in Cargo.toml (via request_sig).
        let buffer_to_sign = sha2::Sha256::digest(cbor_bytes);

        let mut cb_uv_response: u32 = 0;
        let mut pb_uv_response: *mut u8 = std::ptr::null_mut();

        dbg_step!("UV call ...");
        let (uv_hr, uv_tier) = match unsafe { webauthn_ext::perform_user_verification_2(
            req.hwnd,
            &req.transaction_id as *const _,
            username_w.as_ptr(),
            display_hint_w.as_ptr(),
            buffer_to_sign.as_slice(),
            &mut cb_uv_response,
            &mut pb_uv_response,
        ) } {
            Ok(pair) => pair,
            Err(e) => {
                dbg_step!("UV bindings FAILED: {e}");
                return HRESULT(E_FAIL as i32);
            }
        };
        dbg_step!("UV returned hr=0x{:08x} cb_response={cb_uv_response} tier={}",
                  uv_hr.0 as u32, uv_tier.ipc_str());

        // Capture the opaque UV signature bytes before freeing the buffer.
        // Empty vec when cb_uv_response == 0 (matches pbRequestSignatureB64 precedent).
        let uv_sig_bytes: Vec<u8> = if !pb_uv_response.is_null() && cb_uv_response > 0 {
            unsafe { std::slice::from_raw_parts(pb_uv_response, cb_uv_response as usize) }.to_vec()
        } else {
            Vec::new()
        };

        // Free the UV response on EVERY exit path from here on.
        // SAFETY: pb_uv_response is either null (no-op) or the pointer written
        // by perform_user_verification_2 from the Windows runtime allocation.
        unsafe { webauthn_ext::free_user_verification_response(pb_uv_response) };

        if uv_hr.0 as u32 == E_ABORT {
            dbg_step!("UV cancelled by user, returning E_ABORT");
            return uv_hr;
        }
        if uv_hr.is_err() {
            dbg_step!("UV error, propagating hr=0x{:08x}", uv_hr.0 as u32);
            return uv_hr;
        }

        // ── Step 3: UV succeeded — forward to the C# plugin via IPC ──────────
        //
        // 5.UV.2/5.UV.5: pbRequestSignatureB64 is verified by the plugin (sole
        // verifier since 5.UV.5 removed the sidecar-side gate).
        // 5.UV.3: uvSignatureB64 carries the opaque PerformUserVerification(2)
        // response; uvBindingTier records which Windows entrypoint resolved.
        // The plugin logs both in 5.UV.3 and verifies uvSignatureB64 in 5.UV.4.
        let params = serde_json::json!({
            "cbor": cbor_b64,
            "uv": true,
            "pbRequestSignatureB64": sig_b64,
            "uvSignatureB64": base64::engine::general_purpose::STANDARD.encode(&uv_sig_bytes),
            "uvBindingTier": uv_tier.ipc_str(),
        });
        dbg_step!("RPC call {method} (cbor {}B) ...", cbor_bytes.len());

        // 5.UV.8: route through take_call_with_retry so a stale pipe
        // (cached after a plugin process restart while the sidecar is still
        // alive) is recovered transparently — drop dead pipe, reconnect +
        // re-handshake, retry the same RPC with the same params (UV
        // signature already in hand on the stack, so no re-prompt). The
        // helper reconciles `state.pipe` and `SHARED_STATE` internally.
        let result = match take_call_with_retry(&obj.state, method, params, "[dispatch]") {
            Some(r) => r,
            None => {
                dbg_step!("pipe MISSING from state (plugin likely not connected) — returning E_FAIL");
                return HRESULT(E_FAIL as i32);
            }
        };
        dbg_step!("RPC returned");

        match result {
            Ok(v) => {
                let resp_b64 = match v["cbor"].as_str() {
                    Some(s) => s.to_owned(),
                    None => {
                        dbg_step!("RPC ok but response missing 'cbor' string; returning E_FAIL. value={v}");
                        return HRESULT(E_FAIL as i32);
                    }
                };
                let resp_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&resp_b64)
                    .unwrap_or_default();
                dbg_step!("response cbor {}B decoded from base64", resp_bytes.len());

                // ── Phase 4 post-MakeCredential: publish credential to Windows
                //    autofill DB via WebAuthNPluginAuthenticatorAddCredentials.
                //    Best-effort: any failure is logged but does NOT affect the
                //    MakeCredential response returned to webauthn.dll. Without
                //    this call, credentials still register at the RP but the
                //    Windows picker on a later GetAssertion would show "no
                //    passkeys found". See `try_add_credentials` for details.
                try_add_credentials(method, &v);

                let buf = unsafe { CoTaskMemAlloc(resp_bytes.len()) as *mut u8 };
                if buf.is_null() {
                    dbg_step!("CoTaskMemAlloc FAILED");
                    return HRESULT(0x8007_000Eu32 as i32); // E_OUTOFMEMORY
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(resp_bytes.as_ptr(), buf, resp_bytes.len());
                    (*response).cb_encoded_response = resp_bytes.len() as u32;
                    (*response).pb_encoded_response = buf;
                }
                dbg_step!("DONE ok — returning S_OK with {}B to webauthn.dll", resp_bytes.len());
                HRESULT(0)
            }
            Err(ref e @ ClientError::VaultLocked)         => { dbg_step!("RPC err: {e:?} -> E_ACCESSDENIED"); HRESULT(0x8007_0005u32 as i32) }
            Err(ref e @ ClientError::UnsupportedAlgorithm) => { dbg_step!("RPC err: {e:?} -> E_INVALIDARG");  HRESULT(E_INVALIDARG as i32) }
            Err(ref e @ ClientError::CredentialExcluded)   => { dbg_step!("RPC err: {e:?} -> E_CREDENTIAL_EXCLUDED"); HRESULT(E_CREDENTIAL_EXCLUDED as i32) }
            Err(ref e @ ClientError::InvalidOption)        => { dbg_step!("RPC err: {e:?} -> E_INVALIDARG (options.up=false)"); HRESULT(E_INVALIDARG as i32) }
            Err(ClientError::NoCredentials)                => { dbg_step!("GetAssertion -> NoCredentials -> NTE_NOT_FOUND"); HRESULT(0x8009_0011u32 as i32) }
            Err(ref e)                                     => { dbg_step!("RPC err: {e:?} -> E_FAIL"); HRESULT(E_FAIL as i32) }
        }
    }

    /// Post-MakeCredential hook: best-effort publish of the newly created
    /// credential's metadata to Windows' shared autofill / picker database
    /// via `WebAuthNPluginAuthenticatorAddCredentials`.
    ///
    /// Skipped for any method other than `keepasskeywin.makeCredentialRaw`, any
    /// response missing one of the six credential-detail fields, and any
    /// target where the FFI is unavailable. Every failure is logged with
    /// the `[addcreds]` breadcrumb prefix to stderr; NONE change the
    /// caller's return path — the MakeCredential response is still sent
    /// to webauthn.dll and attestation verification at the RP still
    /// succeeds. Only the follow-on login via the Windows picker is
    /// affected by a failure here.
    fn try_add_credentials(method: &str, v: &serde_json::Value) {
        macro_rules! breadcrumb { ($($arg:tt)*) => {
            tracing::debug!("[addcreds] {}", format_args!($($arg)*))
        } }

        if method != "keepasskeywin.makeCredentialRaw" {
            breadcrumb!("skip: not makeCredential (method={method})");
            return;
        }

        let fields = match crate::com::server::parse_add_credentials_fields(v) {
            Ok(f) => f,
            Err(field) => {
                breadcrumb!("skip: response missing field {field}");
                return;
            }
        };

        use crate::com::types::WebauthnPluginCredentialDetails;
        let details = WebauthnPluginCredentialDetails {
            cb_credential_id:       fields.credential_id.len() as u32,
            pb_credential_id:       fields.credential_id.as_ptr(),
            pwsz_rp_id:             fields.rp_id_w.as_ptr(),
            pwsz_rp_name:           fields.rp_name_w.as_ptr(),
            cb_user_id:             fields.user_handle.len() as u32,
            pb_user_id:             fields.user_handle.as_ptr(),
            pwsz_user_name:         fields.user_name_w.as_ptr(),
            pwsz_user_display_name: fields.user_disp_w.as_ptr(),
        };

        // Stringify rp_id / user_name back from the UTF-16 buffers for the
        // breadcrumb — the source &str is already gone by the time the
        // field buffers are owned, and re-walking the Vec<u16> is cheap.
        let rp_id_log:   String = String::from_utf16_lossy(strip_nul(&fields.rp_id_w));
        let user_log:    String = String::from_utf16_lossy(strip_nul(&fields.user_name_w));

        breadcrumb!(
            "calling AddCredentials credId_len={} rpId={rp_id_log} user={user_log}",
            fields.credential_id.len()
        );

        // REFCLSID = pointer-to-GUID. &CLSID_GUID as *const _ — NOT inline
        // bytes (same ABI shape as the register call; different trap would
        // crash immediately).
        let rclsid_ptr = &crate::com::exe_server::CLSID_GUID as *const _;
        match crate::com::webauthnplugin_ext::add_credentials(rclsid_ptr, std::slice::from_ref(&details)) {
            Err(err) => {
                breadcrumb!("skip: FFI not available: {err}");
            }
            Ok(hr) => {
                breadcrumb!("AddCredentials returned hr=0x{:08x}", hr.0 as u32);
                if hr.0 == 0 {
                    breadcrumb!("AddCredentials succeeded — Windows picker should now see this credential");
                }
            }
        }

        // `details` and all its backing Vecs (held in `fields`) drop here.
        // The runtime copied whatever it needed during the call, so freeing
        // the buffers now is safe.
        drop(fields);
    }

    /// Strip the trailing null terminator from a UTF-16 buffer so
    /// `String::from_utf16_lossy` does not render a U+0000 at the end.
    fn strip_nul(w: &[u16]) -> &[u16] {
        match w.last() {
            Some(0) => &w[..w.len() - 1],
            _       => w,
        }
    }

    /// Attempt to extract a user-visible prompt hint from the raw CBOR bytes.
    ///
    /// For `keepasskeywin.makeCredentialRaw` the bytes are a CTAP2 `authenticatorMakeCredential`
    /// map (keys 1-9). Key 3 is `user`, whose `name` field becomes the UV prompt
    /// username. On any parse failure — or for operations that don't carry a username
    /// (GetAssertion) — returns `"KeePassKeyWin"` as the fallback display string.
    pub(crate) fn extract_prompt_hint(cbor_bytes: &[u8], _method: &str) -> String {
        use passkey_types::ctap2::make_credential::Request as MakeCredentialRequest;
        match ciborium::de::from_reader::<MakeCredentialRequest, _>(cbor_bytes) {
            Ok(req) => req.user.name,
            Err(_)  => "KeePassKeyWin".to_string(),
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
            webauthn::{PublicKeyCredentialUserEntity,
                        PublicKeyCredentialParameters, PublicKeyCredentialType},
        };
        use passkey_types::ctap2::make_credential::PublicKeyCredentialRpEntity as CtapRpEntity;

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
            // Single-element [ES256] preserves the pre-5.UV.9.5 fixture surface.
            // `default_algorithms()` returns [ES256, RS256] which would broaden the
            // CBOR payload; the fully-qualified `coset::iana::Algorithm::ES256` path
            // works via passkey-types' re-export without a `use` (which would
            // re-introduce the unused-import warning master had pre-5.UV.9.5).
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
        assert_eq!(extract_prompt_hint(&cbor, "keepasskeywin.makeCredentialRaw"), "alice@example.com");
    }

    #[cfg(windows)]
    #[test]
    fn extract_hint_malformed_cbor_fallback() {
        // A truncated / garbage CBOR blob should not panic and returns "KeePassKeyWin".
        let bad = b"\xff\x00\x01garbage";
        assert_eq!(extract_prompt_hint(bad, "keepasskeywin.makeCredentialRaw"), "KeePassKeyWin");
    }

    #[cfg(windows)]
    #[test]
    fn extract_hint_get_assertion_fallback() {
        // GetAssertion CBOR is a different map shape — parsing as MakeCredential fails → "KeePassKeyWin".
        // Construct a minimal GetAssertion CBOR (key 1 = rpId string).
        let mut buf = Vec::new();
        ciborium::ser::into_writer(
            &ciborium::value::Value::Map(vec![
                (ciborium::value::Value::Integer(1.into()), ciborium::value::Value::Text("example.com".to_string())),
            ]),
            &mut buf,
        ).unwrap();
        assert_eq!(extract_prompt_hint(&buf, "keepasskeywin.getAssertionRaw"), "KeePassKeyWin");
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
    #[cfg(windows)]
    use super::parse_add_credentials_fields;
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

    // ── Phase 4: parse_add_credentials_fields ─────────────────────────────

    /// Helper: base64url-no-pad encode a byte slice. Used to construct
    /// plausible JSON payloads matching the locked wire contract.
    #[cfg(windows)]
    fn b64url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_happy_path() {
        let cred_id = b"\x01\x02\x03\x04\x05";
        let user_id = b"\xaa\xbb\xcc";
        let v = serde_json::json!({
            "cbor": "ignored",
            "credentialIdB64Url": b64url(cred_id),
            "rpId": "example.com",
            "rpName": "Example Site",
            "userHandleB64Url": b64url(user_id),
            "userName": "alice",
            "userDisplayName": "Alice Smith",
        });

        let fields = parse_add_credentials_fields(&v)
            .expect("all six fields present — must decode");

        assert_eq!(fields.credential_id, cred_id.to_vec());
        assert_eq!(fields.user_handle,   user_id.to_vec());

        // Wide strings are null-terminated — compare via from_utf16 after
        // stripping the final zero.
        assert_eq!(fields.rp_id_w.last(),     Some(&0));
        assert_eq!(fields.rp_name_w.last(),   Some(&0));
        assert_eq!(fields.user_name_w.last(), Some(&0));
        assert_eq!(fields.user_disp_w.last(), Some(&0));

        let rp_id = String::from_utf16(&fields.rp_id_w[..fields.rp_id_w.len() - 1]).unwrap();
        assert_eq!(rp_id, "example.com");
        let rp_name = String::from_utf16(&fields.rp_name_w[..fields.rp_name_w.len() - 1]).unwrap();
        assert_eq!(rp_name, "Example Site");
    }

    /// Convenience: run the parser and assert the error path fires with
    /// the given field name. Using a helper keeps each test short and
    /// avoids coupling the test to the (non-PartialEq) success struct.
    #[cfg(windows)]
    fn expect_err(v: &serde_json::Value, expected: &str) {
        match parse_add_credentials_fields(v) {
            Err(got) => assert_eq!(got, expected, "wrong skip-field name"),
            Ok(_)    => panic!("expected Err({expected:?}) but parse succeeded"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_missing_credential_id() {
        let v = serde_json::json!({
            "rpId": "example.com",
            "rpName": "Example",
            "userHandleB64Url": b64url(b"x"),
            "userName": "alice",
            "userDisplayName": "Alice",
        });
        expect_err(&v, "credentialIdB64Url");
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_missing_rp_id() {
        let v = serde_json::json!({
            "credentialIdB64Url": b64url(b"x"),
            "rpName": "Example",
            "userHandleB64Url": b64url(b"x"),
            "userName": "alice",
            "userDisplayName": "Alice",
        });
        expect_err(&v, "rpId");
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_missing_user_display_name() {
        let v = serde_json::json!({
            "credentialIdB64Url": b64url(b"x"),
            "rpId": "example.com",
            "rpName": "Example",
            "userHandleB64Url": b64url(b"x"),
            "userName": "alice",
        });
        expect_err(&v, "userDisplayName");
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_bad_base64() {
        // Padded standard base64 is NOT valid URL-safe-no-pad — decode fails.
        let v = serde_json::json!({
            "credentialIdB64Url": "AAAA==",   // padded '=' invalid for NO_PAD
            "rpId": "example.com",
            "rpName": "Example",
            "userHandleB64Url": b64url(b"x"),
            "userName": "alice",
            "userDisplayName": "Alice",
        });
        expect_err(&v, "credentialIdB64Url decode");
    }

    #[cfg(windows)]
    #[test]
    fn parse_add_credentials_fields_empty_strings_ok() {
        // Microsoft's PluginCredentialManager.cpp validator rejects null
        // but accepts empty strings. Our parser must forward them as
        // non-null null-terminator-only UTF-16 buffers.
        let v = serde_json::json!({
            "credentialIdB64Url": b64url(b"x"),
            "rpId": "",
            "rpName": "",
            "userHandleB64Url": b64url(b"x"),
            "userName": "",
            "userDisplayName": "",
        });
        let fields = parse_add_credentials_fields(&v).expect("empty strings must parse");
        assert_eq!(fields.rp_id_w,     vec![0u16]);
        assert_eq!(fields.rp_name_w,   vec![0u16]);
        assert_eq!(fields.user_name_w, vec![0u16]);
        assert_eq!(fields.user_disp_w, vec![0u16]);
    }
}
