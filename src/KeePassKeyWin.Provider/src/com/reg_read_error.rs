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
//! `lstatus_to_reg_read_error(status, actual_type)` is called by
//! `exe_server::read_handshake_nonce` exactly when the read did NOT yield a
//! valid REG_SZ string. Two entry conditions:
//!
//! * `status != 0` → call with `(status, None)`. The mapper switches on
//!   well-known Windows error codes and falls through to `Other(status)`.
//! * `status == 0 && actual_type != REG_SZ` → call with `(0, Some(actual_type))`.
//!   The mapper returns `WrongType { actual_type }`.
//!
//! Combinations outside these two conditions (e.g. `status == 0, actual_type =
//! Some(1 /*REG_SZ*/)`) are not valid call sites — the caller should have
//! returned `Ok` rather than reaching the error path.

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
    /// Any other LSTATUS code not mapped to a named variant.
    Other(LSTATUS),
}

// ── Pure mapper ───────────────────────────────────────────────────────────────

/// Classify a raw registry read outcome into a [`RegReadError`].
///
/// # Arguments
///
/// * `status` — the raw LSTATUS returned by `RegGetValueW` (passed as `i32`
///   regardless of platform). Zero means the OS call succeeded but the data
///   type is wrong (see `actual_type`).
/// * `actual_type` — the raw `REG_VALUE_TYPE.0` value captured from
///   `RegGetValueW`'s `pdwType` out-param. **Must be `Some(t)`** when
///   `status == 0` (success-with-wrong-type path); ignored when `status != 0`.
///
/// # Mapping
///
/// | `status` | `actual_type` | result |
/// |----------|---------------|--------|
/// | 2 or 3   | any           | `NotFound` |
/// | 5        | any           | `AccessDenied` |
/// | 234      | any           | `BufferTooSmall` |
/// | 0        | `Some(t)`     | `WrongType { actual_type: t }` |
/// | other ≠0 | any           | `Other(status)` |
pub fn lstatus_to_reg_read_error(status: LSTATUS, actual_type: Option<u32>) -> RegReadError {
    // Windows error codes as plain integer constants so this function compiles
    // cross-platform without importing `windows::Win32::Foundation::*`.
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_MORE_DATA: i32 = 234;

    match status {
        0 => {
            // Success status but we reached the error path — the value type is
            // not REG_SZ. `actual_type` is guaranteed Some by the call contract.
            RegReadError::WrongType {
                actual_type: actual_type.unwrap_or(0),
            }
        }
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
        assert_eq!(lstatus_to_reg_read_error(2, None), RegReadError::NotFound);
    }

    #[test]
    fn error_path_not_found_maps_to_not_found() {
        // ERROR_PATH_NOT_FOUND = 3 — the sub-key path doesn't exist.
        assert_eq!(lstatus_to_reg_read_error(3, None), RegReadError::NotFound);
    }

    // ── AccessDenied ─────────────────────────────────────────────────────────

    #[test]
    fn error_access_denied_maps_to_access_denied() {
        // ERROR_ACCESS_DENIED = 5.
        assert_eq!(
            lstatus_to_reg_read_error(5, None),
            RegReadError::AccessDenied,
        );
    }

    // ── BufferTooSmall ───────────────────────────────────────────────────────

    #[test]
    fn error_more_data_maps_to_buffer_too_small() {
        // ERROR_MORE_DATA = 234 — value exists but buffer was undersized.
        assert_eq!(
            lstatus_to_reg_read_error(234, None),
            RegReadError::BufferTooSmall,
        );
    }

    // ── WrongType ────────────────────────────────────────────────────────────

    #[test]
    fn success_with_reg_dword_maps_to_wrong_type() {
        // status == 0, actual_type == REG_DWORD (4).
        assert_eq!(
            lstatus_to_reg_read_error(0, Some(4)),
            RegReadError::WrongType { actual_type: 4 },
        );
    }

    #[test]
    fn success_with_reg_binary_maps_to_wrong_type() {
        // status == 0, actual_type == REG_BINARY (3).
        assert_eq!(
            lstatus_to_reg_read_error(0, Some(3)),
            RegReadError::WrongType { actual_type: 3 },
        );
    }

    #[test]
    fn success_with_reg_multi_sz_maps_to_wrong_type() {
        // status == 0, actual_type == REG_MULTI_SZ (7).
        assert_eq!(
            lstatus_to_reg_read_error(0, Some(7)),
            RegReadError::WrongType { actual_type: 7 },
        );
    }

    // ── Other ─────────────────────────────────────────────────────────────────

    #[test]
    fn unknown_status_maps_to_other() {
        // An arbitrary non-zero LSTATUS not in the named variants.
        // 6 = ERROR_INVALID_HANDLE, 87 = ERROR_INVALID_PARAMETER.
        assert_eq!(
            lstatus_to_reg_read_error(6, None),
            RegReadError::Other(6),
        );
        assert_eq!(
            lstatus_to_reg_read_error(87, None),
            RegReadError::Other(87),
        );
    }

    #[test]
    fn negative_status_maps_to_other() {
        // Some registry functions can return negative LSTATUS values
        // (though rare). Verify Other captures the sign correctly.
        assert_eq!(
            lstatus_to_reg_read_error(-1, None),
            RegReadError::Other(-1),
        );
    }
}
