//! Decision helpers for the v2→v1 call-time fallback (Phase 5.UV.7).
//!
//! Lives outside `webauthn_ext.rs` so the helpers and their tests compile on
//! Linux CI (the parent module is `#![cfg(windows)]` because of its FFI
//! surface). The HRESULT shim mirrors the pattern in `request_sig.rs`:
//! re-export the real `windows::core::HRESULT` on Windows, define a
//! compatible newtype on Linux so tests can construct values directly.
//!
//! Background: Win11 24H2 26100.6725+ exports
//! `WebAuthNPluginPerformUserVerification2` as a forward-declared stub that
//! returns `E_NOTIMPL` (0x80004001) when called, even though the symbol
//! resolves at load time. `webauthn_ext::perform_user_verification_2` does a
//! call-time fallback to v1 when v2 returns `E_NOTIMPL` and caches the
//! decision per-process; the helpers here own (a) the HRESULT classifier
//! and (b) the cache mutation so the fragile bits are unit-testable on
//! Linux without an FFI harness.

use std::sync::atomic::{AtomicBool, Ordering};

// ── HRESULT type ──────────────────────────────────────────────────────────────
//
// On Windows we re-export the real `windows::core::HRESULT` so callers in
// `webauthn_ext` (windows-only) can pass values without conversion. On
// non-Windows we define a compatible newtype with the same shape so tests
// run on Linux CI without pulling in the `windows` crate.

#[cfg(windows)]
pub use windows::core::HRESULT;

/// Minimal HRESULT newtype for non-Windows builds. Same shape as
/// `windows::core::HRESULT(i32)` — `.0` field, constructable from any `i32`.
#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HRESULT(pub i32);

// ── Fallback decision ─────────────────────────────────────────────────────────

/// Returns `true` iff the helper should fall back to v1 in this dispatch
/// based on the v2 result. `E_NOTIMPL` (0x80004001) is the only HRESULT that
/// triggers fallback; all other errors propagate as-is.
///
/// `E_ABORT` (user-cancel) must not trigger fallback — the user's
/// cancellation must propagate so the next dispatch in the process still
/// tries v2 rather than silently re-prompting via v1.
#[inline]
pub fn should_fallback_to_v1(v2_hr: HRESULT) -> bool {
    v2_hr.0 as u32 == 0x80004001 // E_NOTIMPL
}

/// Updates the per-process v2-unimplemented cache based on the v2 call's
/// HRESULT. Sets the flag iff the HRESULT was `E_NOTIMPL`; leaves it alone
/// otherwise. This is the single authoritative write site for the cache —
/// `webauthn_ext::perform_user_verification_2` calls this after every v2
/// invocation so the test exercises the same code path as production.
///
/// `Ordering::Relaxed` is correct here: there is no shared data being
/// protected by the flag — only the flag's own state — so Acquire/Release
/// or SeqCst would be over-ordering with no benefit.
#[inline]
pub fn observe_v2_result(cache: &AtomicBool, hr: HRESULT) {
    if should_fallback_to_v1(hr) {
        cache.store(true, Ordering::Relaxed);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── should_fallback_to_v1 classifier ─────────────────────────────────────

    #[test]
    fn e_notimpl_triggers_fallback() {
        // E_NOTIMPL = 0x80004001 — the only HRESULT that triggers v1 fallback.
        assert!(should_fallback_to_v1(HRESULT(0x80004001u32 as i32)));
    }

    #[test]
    fn s_ok_does_not_trigger_fallback() {
        assert!(!should_fallback_to_v1(HRESULT(0)));
    }

    #[test]
    fn e_abort_does_not_trigger_fallback() {
        // E_ABORT (0x80004004) — user-cancel must propagate, not silently
        // re-prompt via v1; the next dispatch must still try v2.
        assert!(!should_fallback_to_v1(HRESULT(0x80004004u32 as i32)));
    }

    #[test]
    fn other_errors_do_not_trigger_fallback() {
        // E_FAIL
        assert!(!should_fallback_to_v1(HRESULT(0x80004005u32 as i32)));
        // E_INVALIDARG
        assert!(!should_fallback_to_v1(HRESULT(0x80070057u32 as i32)));
        // E_OUTOFMEMORY
        assert!(!should_fallback_to_v1(HRESULT(0x8007000Eu32 as i32)));
    }

    // ── observe_v2_result cache mutation ─────────────────────────────────────

    #[test]
    fn observe_v2_result_flips_cache_on_e_notimpl_only() {
        let cache = AtomicBool::new(false);

        // S_OK — cache stays false.
        observe_v2_result(&cache, HRESULT(0));
        assert!(!cache.load(Ordering::Relaxed), "S_OK must not poison the cache");

        // E_ABORT — cache stays false.
        observe_v2_result(&cache, HRESULT(0x80004004u32 as i32));
        assert!(!cache.load(Ordering::Relaxed), "E_ABORT must not poison the cache");

        // E_FAIL — cache stays false.
        observe_v2_result(&cache, HRESULT(0x80004005u32 as i32));
        assert!(!cache.load(Ordering::Relaxed), "E_FAIL must not poison the cache");

        // E_NOTIMPL — cache flips to true (one-way latch).
        observe_v2_result(&cache, HRESULT(0x80004001u32 as i32));
        assert!(cache.load(Ordering::Relaxed), "E_NOTIMPL must poison the cache");

        // S_OK after E_NOTIMPL — cache stays true (latch is one-way).
        observe_v2_result(&cache, HRESULT(0));
        assert!(cache.load(Ordering::Relaxed), "latch must remain set after S_OK");
    }
}
