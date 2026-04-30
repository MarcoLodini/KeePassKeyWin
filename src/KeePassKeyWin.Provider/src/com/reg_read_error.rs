// SPDX-License-Identifier: GPL-3.0-or-later
//! Faithful registry-error classification for `read_handshake_nonce` (5.UV.9).
//!
//! Lives outside `exe_server.rs` so the pure mapper and its tests compile on
//! Linux CI (the parent `com::exe_server` module is `#[cfg(windows)]`). Mirrors
//! the cross-platform pattern of `uv_fallback.rs` (5.UV.7) and
//! `classify_rpc_error.rs` (5.UV.8): a small enum returned by a pure classifier,
//! plus a `#[cfg(windows)]` / newtype shim pair so the type is constructable
//! in unit tests without the `windows` crate.
//!
//! ## Mapping contract
//!
//! `lstatus_to_reg_read_error(status)` classifies the LSTATUS returned by a
//! failed `RegGetValueW` call. The caller MUST pass a non-zero `status` —
//! the success-path variants (`WrongType`, `MalformedString`) are constructed
//! directly at the call site in `exe_server::read_handshake_nonce` because
//! they need data that is not available to a pure LSTATUS classifier (the
//! `actual_type` out-param and the post-decode UTF-16 result respectively).
//! A `debug_assert!` enforces the non-zero contract; release builds fall
//! through to `Other(0)`.

/// LSTATUS is `i32` on Windows (`windows::Win32::Foundation::WIN32_ERROR` underlying type)
/// and a plain `i32` alias everywhere else so the pure mapper compiles on Linux CI.
#[cfg(windows)]
pub use windows::Win32::Foundation::WIN32_ERROR as WIN32_ERROR_TYPE;

/// Flat `i32` alias for non-Windows builds — same shape as the raw status int.
pub type LSTATUS = i32;

// ── RegReadError ──────────────────────────────────────────────────────────────

/// Failure variants for reading `HKCU\Software\KeePassKeyWin\HandshakeNonce`.
///
/// Each variant maps to a distinct, human-readable `ClientError::InvalidRequest`
/// message in `connect_and_handshake` so a user staring at the log line can
/// immediately distinguish "key absent" from "wrong type" from "access denied"
/// from other registry failures.
#[derive(Debug, PartialEq, Eq)]
pub enum RegReadError {
    /// The registry key or value does not exist (ERROR_FILE_NOT_FOUND = 2,
    /// or ERROR_PATH_NOT_FOUND = 3).
    NotFound,
    /// The value exists but has the wrong REG type. `actual_type` is the raw
    /// `REG_VALUE_TYPE.0` integer (e.g. 4 for REG_DWORD, 3 for REG_BINARY).
    /// REG_SZ = 1 is the expected type.
    WrongType { actual_type: u32 },
    /// The caller does not have permission to read the key
    /// (ERROR_ACCESS_DENIED = 5).
    AccessDenied,
    /// The value exists but the read buffer was too small
    /// (ERROR_MORE_DATA = 234).
    BufferTooSmall,
    /// The value is REG_SZ but its raw bytes are not valid UTF-16
    /// (corrupted value, partial write, encoding mismatch). Constructed
    /// directly at the post-decode site in `read_handshake_nonce` — not
    /// produced by `lstatus_to_reg_read_error` (the LSTATUS itself is
    /// `ERROR_SUCCESS`; the failure is at the byte-content layer).
    MalformedString,
    /// Any other LSTATUS code not mapped to a named variant.
    Other(LSTATUS),
}

// ── Pure mapper ───────────────────────────────────────────────────────────────

/// Classify a non-zero LSTATUS from `RegGetValueW` into a [`RegReadError`].
///
/// Caller MUST pass a non-zero `status` — `WrongType` (success-with-wrong-type)
/// and `MalformedString` (success-but-bad-UTF-16) are constructed directly
/// at the call site because they need data the LSTATUS classifier doesn't
/// have. A `debug_assert!` enforces the contract; release builds with
/// `status == 0` fall through to `Other(0)`, which is misleading but
/// unreachable in production.
///
/// # Mapping
///
/// | `status`   | result |
/// |------------|--------|
/// | 2 or 3     | `NotFound` |
/// | 5          | `AccessDenied` |
/// | 234        | `BufferTooSmall` |
/// | other ≠ 0  | `Other(status)` |
pub fn lstatus_to_reg_read_error(status: LSTATUS) -> RegReadError {
    debug_assert!(
        status != 0,
        "lstatus_to_reg_read_error called with status=0; \
         success-path variants are constructed at the call site"
    );
    // Windows error codes as plain integer constants so this function compiles
    // cross-platform without importing `windows::Win32::Foundation::*`.
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_MORE_DATA: i32 = 234;

    match status {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => RegReadError::NotFound,
        ERROR_ACCESS_DENIED => RegReadError::AccessDenied,
        ERROR_MORE_DATA => RegReadError::BufferTooSmall,
        other => RegReadError::Other(other),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NotFound ─────────────────────────────────────────────────────────────

    #[test]
    fn error_file_not_found_maps_to_not_found() {
        // ERROR_FILE_NOT_FOUND = 2 — the key/value is absent.
        assert_eq!(lstatus_to_reg_read_error(2), RegReadError::NotFound);
    }

    #[test]
    fn error_path_not_found_maps_to_not_found() {
        // ERROR_PATH_NOT_FOUND = 3 — the sub-key path doesn't exist.
        assert_eq!(lstatus_to_reg_read_error(3), RegReadError::NotFound);
    }

    // ── AccessDenied ─────────────────────────────────────────────────────────

    #[test]
    fn error_access_denied_maps_to_access_denied() {
        // ERROR_ACCESS_DENIED = 5.
        assert_eq!(lstatus_to_reg_read_error(5), RegReadError::AccessDenied);
    }

    // ── BufferTooSmall ───────────────────────────────────────────────────────

    #[test]
    fn error_more_data_maps_to_buffer_too_small() {
        // ERROR_MORE_DATA = 234 — value exists but buffer was undersized.
        assert_eq!(lstatus_to_reg_read_error(234), RegReadError::BufferTooSmall);
    }

    // ── Other ─────────────────────────────────────────────────────────────────

    #[test]
    fn unknown_status_maps_to_other() {
        // Arbitrary non-zero LSTATUS values not in the named variants.
        // 6 = ERROR_INVALID_HANDLE, 87 = ERROR_INVALID_PARAMETER.
        assert_eq!(lstatus_to_reg_read_error(6), RegReadError::Other(6));
        assert_eq!(lstatus_to_reg_read_error(87), RegReadError::Other(87));
    }

    #[test]
    fn negative_status_maps_to_other() {
        // Some registry functions can return negative LSTATUS values
        // (though rare). Verify Other captures the sign correctly.
        assert_eq!(lstatus_to_reg_read_error(-1), RegReadError::Other(-1));
    }
}
