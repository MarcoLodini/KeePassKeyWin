//! Debug overrides for the PerformUserVerification binding lookup.
//!
//! On 24H2 26100.6725+ the `_2` symbol resolves and every UV op lands on
//! `v2_experimental`, so the `v1` branch (and the plugin-side fallback
//! confirmation dialog wired in 5.UV.4) is unreachable in normal traffic.
//! This module provides one env-var override that lets us exercise the v1
//! path end-to-end on a real Windows machine for acceptance testing.
//!
//! `KEEPASSKEYWIN_FORCE_UV_V1=1` — when set at sidecar process start,
//! `webauthn_ext::bindings()` skips the v2 lookup entirely and resolves to
//! `WebAuthNPluginPerformUserVerification` (v1) for every dispatch. The IPC
//! `uvBindingTier` field is then `"v1"`, which triggers the plugin's
//! once-per-process confirmation dialog.
//!
//! The check is read once per process at first-bindings init (cached in a
//! `OnceLock`); flipping the env var mid-session has no effect on a
//! long-running sidecar, but the COM activation model spawns a fresh
//! sidecar process per op so a `setx` between dispatches is enough.
//!
//! Module is cross-platform (no `#[cfg(windows)]`) so its tests run in CI.

/// Returns `true` when `KEEPASSKEYWIN_FORCE_UV_V1` is set to a truthy value.
/// Truthy means `"1" | "true" | "yes"` after `trim` + `to_ascii_lowercase`,
/// matching the existing `KEEPASSKEYWIN_SKIP_REQUEST_SIG_VERIFY` convention
/// (`request_sig::is_bypass_enabled`). Anything else — including `"0"`,
/// `"false"`, empty, unset — leaves the production v2-lookup path active.
pub fn force_v1_enabled() -> bool {
    match std::env::var("KEEPASSKEYWIN_FORCE_UV_V1") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAR: &str = "KEEPASSKEYWIN_FORCE_UV_V1";

    // Helper: save current value, run closure, restore. Mirrors the
    // request_sig::tests pattern. Not #[serial] because std::env::set_var is
    // safe on stable Rust ≤ 1.82; tracked as a follow-up to add serial_test
    // when the toolchain bumps past 1.82 (memory note).
    fn with_env<F: FnOnce()>(value: Option<&str>, f: F) {
        let prev = std::env::var(VAR).ok();
        match value {
            Some(v) => std::env::set_var(VAR, v),
            None => std::env::remove_var(VAR),
        }
        f();
        match prev {
            Some(v) => std::env::set_var(VAR, v),
            None => std::env::remove_var(VAR),
        }
    }

    #[test]
    fn force_v1_enabled_truthy_values() {
        for v in &["1", "true", "TRUE", "True", "yes", "YES", "Yes", " 1 ", "  true  "] {
            with_env(Some(v), || {
                assert!(force_v1_enabled(), "expected true for value={v:?}");
            });
        }
    }

    #[test]
    fn force_v1_disabled_when_var_absent() {
        with_env(None, || assert!(!force_v1_enabled()));
    }

    #[test]
    fn force_v1_disabled_falsy_values() {
        for v in &["0", "false", "FALSE", "no", "off", "", "v1", "11"] {
            with_env(Some(v), || {
                assert!(!force_v1_enabled(), "expected false for value={v:?}");
            });
        }
    }
}
