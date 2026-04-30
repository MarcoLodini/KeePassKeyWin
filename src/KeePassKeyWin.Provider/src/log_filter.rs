//! Pre-validation of log-filter directives with warning capture.
//!
//! [`EnvFilter`]'s lossy parsing methods (`from_env_lossy`, `parse_lossy`)
//! emit per-directive parse warnings to stderr via `eprintln!`. Under
//! `windows_subsystem = "windows"` the COM-activated sidecar's stderr is a
//! closed handle, making those warnings invisible — a typo in e.g.
//! `KEEPASSKEYWIN_LOG_LEVEL` silently discards that directive with no
//! user-visible signal. This module closes that gap.
//!
//! It pre-validates each comma-separated directive via
//! [`Directive::from_str`]. Valid directives are joined back into a string
//! that is guaranteed warning-free for `parse_lossy`; rejected directives are
//! collected as structured warnings that the caller re-emits through the
//! tracing subscriber (e.g. via [`tracing::warn!`]) after initialisation,
//! routing them through whichever sink (file, stderr, etc.) the subscriber
//! provides.
//!
//! The module is cross-platform and pure (string-in, strings-out), so the
//! parser tests run on Linux CI rather than being Windows-only.

use tracing_subscriber::filter::Directive;

/// Result of pre-parsing a comma-separated log-level directive string.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LogFilterParse {
    /// Joined directive string containing only the parts that parsed
    /// successfully — safe to feed to `EnvFilter::parse_lossy` without
    /// triggering any further warnings.
    pub good_directives: String,
    /// Human-readable warnings, one per rejected directive. Format:
    /// `"<env-var>: rejected directive '<part>': <error>"`.
    pub warnings: Vec<String>,
}

/// Parse a `RUST_LOG`-style comma-separated directive string, partitioning
/// successfully-parseable directives from invalid ones.
///
/// `env_var_name` is interpolated into warnings so the message identifies
/// which env var the user mistyped (e.g., `KEEPASSKEYWIN_LOG_LEVEL`).
///
/// Each comma-separated part is trimmed and validated via
/// `tracing_subscriber::filter::Directive::from_str`. Empty parts (e.g.,
/// from `"foo,,bar"` or trailing comma) are silently dropped — they are
/// not user errors, just whitespace artifacts.
pub fn parse(raw: &str, env_var_name: &str) -> LogFilterParse {
    let mut good: Vec<&str> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match part.parse::<Directive>() {
            Ok(_) => good.push(part),
            Err(e) => warnings.push(format!(
                "{env_var_name}: rejected directive {part:?}: {e}"
            )),
        }
    }

    LogFilterParse {
        good_directives: good.join(","),
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_output() {
        let r = parse("", "X");
        assert_eq!(r.good_directives, "");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn whitespace_only_input_yields_empty_output() {
        let r = parse("   ,, ,  ", "X");
        assert_eq!(r.good_directives, "");
        assert!(r.warnings.is_empty(), "blank parts must not produce warnings");
    }

    #[test]
    fn single_top_level_level_passes() {
        let r = parse("info", "X");
        assert_eq!(r.good_directives, "info");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn target_level_directive_passes() {
        let r = parse("keepasskeywin_provider=debug", "X");
        assert_eq!(r.good_directives, "keepasskeywin_provider=debug");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn comma_separated_mix_preserves_order() {
        let r = parse("info,foo=debug,bar=trace", "X");
        assert_eq!(r.good_directives, "info,foo=debug,bar=trace");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn invalid_level_string_is_rejected_with_warning() {
        // "bogus" is not a valid level — should be captured, not passed through.
        let r = parse("foo=bogus", "MY_VAR");
        assert_eq!(r.good_directives, "");
        assert_eq!(r.warnings.len(), 1);
        let w = &r.warnings[0];
        assert!(w.contains("MY_VAR"), "warning must name the env var: {w}");
        assert!(w.contains("foo=bogus"), "warning must echo the bad part: {w}");
    }

    #[test]
    fn mixed_good_and_bad_partitions_correctly() {
        // First directive valid; second invalid; third valid.
        let r = parse("info,foo=bogus,bar=debug", "MY_VAR");
        assert_eq!(r.good_directives, "info,bar=debug");
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("foo=bogus"));
    }

    #[test]
    fn warning_format_quotes_the_part() {
        // Use Rust's Debug formatter ({:?}) so unusual chars are visible.
        let r = parse("=", "X");
        assert_eq!(r.good_directives, "");
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("\"=\""));
    }

    #[test]
    fn whitespace_around_directive_is_trimmed() {
        let r = parse("  info  ,  foo=debug  ", "X");
        assert_eq!(r.good_directives, "info,foo=debug");
        assert!(r.warnings.is_empty());
    }
}
