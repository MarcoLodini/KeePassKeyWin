//! JSON-RPC error classifier + slot-clearing helper for the inline stale-pipe
//! retry path (Phase 5.UV.8).
//!
//! Lives outside `server.rs` so the helpers and their tests compile on Linux
//! CI (the `com::server` parent module is `#[cfg(windows)]`). Mirrors the
//! shape of `uv_fallback.rs` (5.UV.7): a pure classifier returning a small
//! enum, plus a state-mutation helper kept generic so a stub-T unit test
//! exercises the same code path as production.
//!
//! Background: the sidecar caches the plugin pipe handle in process-wide
//! `SHARED_STATE` after the first successful `keepasskeywin.hello` handshake
//! (`com::exe_server::cf_create_instance`). If the plugin restarts (KeePass
//! shutdown + relaunch) while the sidecar is still alive, the cached handle
//! goes stale; the next dispatch's pipe write produces
//! `Io(Os { code: 232, kind: BrokenPipe })`. The dispatch helper at
//! `server::take_call_with_retry` classifies the error via the function
//! below; on `Stale` it drops the dead pipe, reconnects + re-handshakes via
//! `exe_server::connect_and_handshake`, and retries the call once with the
//! same params. On retry-connect/handshake failure, `clear_slot` (via
//! `exe_server::clear_shared_state`) nulls the SHARED_STATE outer slot so
//! the next COM activation reconnects from scratch.

use std::sync::Mutex;

use crate::ipc::ClientError;

// ── RpcErrorClass ─────────────────────────────────────────────────────────────

/// Classification result for a JSON-RPC call error in the dispatch path.
///
/// `Stale` triggers the inline reconnect+retry; `Other` propagates as-is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcErrorClass {
    Stale,
    Other,
}

/// Classify a `ClientError` for stale-pipe retry decisions.
///
/// `Io(BrokenPipe)` and `Io(ConnectionAborted)` map to `Stale`; everything
/// else is `Other`. `UnexpectedEof` and `NotConnected` are deliberately
/// `Other` for v1 — the empirical signal at 5.UV.8 surface time was
/// specifically `BrokenPipe` (Windows ERROR_BROKEN_PIPE = 232; tokio's
/// named-pipe transport surfaces both write-after-peer-close and
/// read-after-peer-close as this kind on Windows). The cost asymmetry
/// favours conservative Stale-classification: a false-`Other` makes the
/// user see the bug we're fixing, while a false-`Stale` is just an
/// unnecessary retry that probably succeeds anyway. Broaden the match arm
/// only when a follow-up shows another kind in the wild.
#[inline]
pub fn classify_rpc_error(err: &ClientError) -> RpcErrorClass {
    match err {
        ClientError::Io(io_err) => match io_err.kind() {
            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionAborted => {
                RpcErrorClass::Stale
            }
            _ => RpcErrorClass::Other,
        },
        _ => RpcErrorClass::Other,
    }
}

// ── clear_slot — generic outer-Mutex<Option<T>> helper ───────────────────────

/// Set a `Mutex<Option<T>>` slot to `None`, dropping any contained value.
///
/// Generic so the test below runs on Linux CI with a stub `T` — the
/// production wrapper `exe_server::clear_shared_state` instantiates `T` at
/// `Arc<Mutex<KeePassKeyWinAuthenticatorState>>` (Windows-only types). The
/// helper is intentionally type-shallow: it only mutates the outer
/// `Mutex<Option<_>>`, so a richer `&Mutex<Option<Arc<Mutex<U>>>>` signature
/// would over-fit the SHARED_STATE shape without earning any test coverage.
/// Callers that need Arc-clone-safety semantics (see `clear_slot_drops_inner_arc`)
/// instantiate `T = Arc<Mutex<U>>` and the test still verifies strong-count
/// drops correctly.
///
/// The 5.UV.8 retry path calls this when reconnect+rehandshake fails
/// during a retry: clearing the slot is the load-bearing step that prevents
/// the next COM activation reusing a half-dead Arc whose inner pipe is
/// permanently `None` (which would short-circuit every future dispatch at
/// the entry-side `take()` in `server::take_call_with_retry`).
///
/// Race-safety: callers may hold their own `Arc` clones of the same
/// allocation; clearing the slot only drops the slot's clone, leaving
/// in-flight dispatches' Arc clones intact. `strong_count` does not reach
/// zero just because this slot is cleared.
#[inline]
pub fn clear_slot<T>(slot: &Mutex<Option<T>>) {
    *slot.lock().unwrap() = None;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;

    // ── classify_rpc_error: Stale arms ───────────────────────────────────────

    #[test]
    fn broken_pipe_is_stale() {
        let e = ClientError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "broken"));
        assert_eq!(classify_rpc_error(&e), RpcErrorClass::Stale);
    }

    #[test]
    fn connection_aborted_is_stale() {
        let e = ClientError::Io(io::Error::new(io::ErrorKind::ConnectionAborted, "aborted"));
        assert_eq!(classify_rpc_error(&e), RpcErrorClass::Stale);
    }

    // ── classify_rpc_error: deliberately Other Io kinds ──────────────────────

    #[test]
    fn unexpected_eof_is_other_for_v1() {
        // Deliberately Other — see module docs. Broaden only on live evidence.
        let e = ClientError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
        assert_eq!(classify_rpc_error(&e), RpcErrorClass::Other);
    }

    #[test]
    fn not_connected_is_other_for_v1() {
        let e = ClientError::Io(io::Error::new(io::ErrorKind::NotConnected, "no"));
        assert_eq!(classify_rpc_error(&e), RpcErrorClass::Other);
    }

    #[test]
    fn other_io_kinds_are_other() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::InvalidData,
            io::ErrorKind::Interrupted,
        ] {
            let e = ClientError::Io(io::Error::new(kind, "x"));
            assert_eq!(
                classify_rpc_error(&e),
                RpcErrorClass::Other,
                "unexpected Stale classification for {kind:?}",
            );
        }
    }

    // ── classify_rpc_error: non-Io ClientError variants ──────────────────────

    #[test]
    fn vault_locked_is_other() {
        assert_eq!(classify_rpc_error(&ClientError::VaultLocked), RpcErrorClass::Other);
    }

    #[test]
    fn no_credentials_is_other() {
        assert_eq!(classify_rpc_error(&ClientError::NoCredentials), RpcErrorClass::Other);
    }

    #[test]
    fn timeout_is_other() {
        assert_eq!(classify_rpc_error(&ClientError::Timeout), RpcErrorClass::Other);
    }

    #[test]
    fn rpc_error_is_other() {
        let e = ClientError::RpcError { code: -99, message: "x".into() };
        assert_eq!(classify_rpc_error(&e), RpcErrorClass::Other);
    }

    #[test]
    fn unsupported_algorithm_is_other() {
        assert_eq!(
            classify_rpc_error(&ClientError::UnsupportedAlgorithm),
            RpcErrorClass::Other,
        );
    }

    // ── clear_slot ───────────────────────────────────────────────────────────

    #[test]
    fn clear_slot_drops_inner_arc() {
        // Stub T = i32. Arc strong-count visible without needing the real
        // Windows-only KeePassKeyWinAuthenticatorState.
        let inner = Arc::new(Mutex::new(99i32));
        let slot: Mutex<Option<Arc<Mutex<i32>>>> = Mutex::new(Some(inner.clone()));

        assert_eq!(Arc::strong_count(&inner), 2, "slot + outer ref");
        clear_slot(&slot);
        assert_eq!(Arc::strong_count(&inner), 1, "slot's clone must drop");
        assert!(slot.lock().unwrap().is_none(), "slot must be None after clear");
    }

    #[test]
    fn clear_slot_idempotent_on_empty() {
        let slot: Mutex<Option<Arc<Mutex<i32>>>> = Mutex::new(None);
        clear_slot(&slot);
        assert!(slot.lock().unwrap().is_none());
    }

    #[test]
    fn clear_slot_does_not_invalidate_other_arc_clones() {
        // Load-bearing for 5.UV.8: an in-flight dispatch holds its own
        // Arc clone of the same allocation. Clearing the SHARED_STATE slot
        // must NOT invalidate that clone — the in-flight dispatch must be
        // able to finish its work on the existing State.
        let allocation = Arc::new(Mutex::new(7i32));
        let in_flight_clone = allocation.clone();
        let slot: Mutex<Option<Arc<Mutex<i32>>>> = Mutex::new(Some(allocation));

        clear_slot(&slot);

        // Other clone still holds the value.
        assert_eq!(*in_flight_clone.lock().unwrap(), 7);
        // And mutation through the surviving clone still works.
        *in_flight_clone.lock().unwrap() = 42;
        assert_eq!(*in_flight_clone.lock().unwrap(), 42);
    }
}
