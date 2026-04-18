//! Raw FFI types transcribed from idl/pluginauthenticator.h.
//!
//! These are ABI-compatible with the MIDL-generated structs. All types are
//! repr(C) and use Windows primitive types (DWORD = u32, HWND = isize, etc.)
//! matching the x86-64 Windows ABI.

// ── Enums ────────────────────────────────────────────────────────────────────

/// Maps to `WEBAUTHN_PLUGIN_REQUEST_TYPE` in pluginauthenticator.h.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebauthNPluginRequestType {
    Ctap2Cbor = 0x1,
}

/// Maps to `PLUGIN_LOCK_STATUS` in pluginauthenticator.h.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginLockStatus {
    Locked   = 0,
    Unlocked = 1,
}

// ── Structs ───────────────────────────────────────────────────────────────────

/// Corresponds to `GUID` / `CLSID` in Windows headers (128-bit UUID, specific layout).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Maps to `WEBAUTHN_PLUGIN_OPERATION_REQUEST`.
///
/// Layout (x86-64, packed per MIDL defaults):
///   HWND  hWnd                 (8 bytes — pointer-sized)
///   GUID  transactionId        (16 bytes)
///   DWORD cbRequestSignature   (4 bytes)
///   byte* pbRequestSignature   (8 bytes pointer)
///   DWORD requestType          (4 bytes — enum)
///   DWORD cbEncodedRequest     (4 bytes)
///   byte* pbEncodedRequest     (8 bytes pointer)
#[repr(C)]
pub struct WebauthNPluginOperationRequest {
    pub hwnd: isize,                        // HWND
    pub transaction_id: Guid,               // GUID
    pub cb_request_signature: u32,          // DWORD
    pub pb_request_signature: *const u8,    // byte*
    pub request_type: WebauthNPluginRequestType,
    pub cb_encoded_request: u32,            // DWORD
    pub pb_encoded_request: *const u8,      // byte*
}

unsafe impl Send for WebauthNPluginOperationRequest {}
unsafe impl Sync for WebauthNPluginOperationRequest {}

impl WebauthNPluginOperationRequest {
    /// Returns the encoded CBOR request bytes as a slice.
    ///
    /// # Safety
    /// Caller must ensure `pb_encoded_request` is valid for `cb_encoded_request` bytes.
    pub unsafe fn encoded_request(&self) -> &[u8] {
        std::slice::from_raw_parts(self.pb_encoded_request, self.cb_encoded_request as usize)
    }
}

/// Maps to `WEBAUTHN_PLUGIN_OPERATION_RESPONSE`.
///
/// The COM server allocates `pbEncodedResponse` with `CoTaskMemAlloc`;
/// the caller (Windows WebAuthn API) frees it with `CoTaskMemFree`.
#[repr(C)]
pub struct WebauthNPluginOperationResponse {
    pub cb_encoded_response: u32,
    pub pb_encoded_response: *mut u8,
}

impl Default for WebauthNPluginOperationResponse {
    fn default() -> Self {
        Self {
            cb_encoded_response: 0,
            pb_encoded_response: std::ptr::null_mut(),
        }
    }
}

unsafe impl Send for WebauthNPluginOperationResponse {}
unsafe impl Sync for WebauthNPluginOperationResponse {}

/// Maps to `WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST`.
#[repr(C)]
pub struct WebauthNPluginCancelOperationRequest {
    pub transaction_id: Guid,
    pub cb_request_signature: u32,
    pub pb_request_signature: *const u8,
}

unsafe impl Send for WebauthNPluginCancelOperationRequest {}
unsafe impl Sync for WebauthNPluginCancelOperationRequest {}

// ── IID constant ──────────────────────────────────────────────────────────────

/// IID_IPluginAuthenticator = {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
pub const IID_IPLUGIN_AUTHENTICATOR: Guid = Guid {
    data1: 0xd26b_cf6f,
    data2: 0xb54c,
    data3: 0x43ff,
    data4: [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7],
};

// ── EXPERIMENTAL_ WebAuthN plugin registration structs ────────────────────────
//
// Map to `EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS` and
// `EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE` in webauthn.h
// (Windows 11 SDK 10.0.26100.0+). The `EXPERIMENTAL_` prefix is Microsoft's
// marker for unstable APIs — expect field renames / additions between SDK
// revisions; re-verify on every SDK bump. No version constant exists at the
// struct level (unlike many other windows-sdk plugin APIs).

/// Maps to `WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS` in the newer SDK
/// shape (10.0.26100.7175+) — what Windows 11 25H2 (build 26200.x) actually
/// expects at runtime, even when invoked via the legacy `EXPERIMENTAL_`
/// symbol. The older shape (`pwszPluginClsId: LPCWSTR`, no logo `Svg`
/// suffix, no `SupportedRpIds`) shipped in SDK 10.0.26100.0 but the runtime
/// DLL was updated out-of-band; passing the old shape produces an opaque
/// 0x80090027 NTE_INVALID_PARAMETER because the runtime reinterprets our
/// string pointer as inline GUID bytes.
///
/// x64 layout (80 bytes):
///   offset 0:  pwsz_authenticator_name    (ptr, 8)
///   offset 8:  rclsid                     (Guid, 16 — inline, NOT a pointer)
///   offset 24: pwsz_plugin_rp_id          (ptr, 8)   // required by runtime even though doc says "optional"
///   offset 32: pwsz_light_theme_logo_svg  (ptr, 8)   // optional base64 SVG 1.1
///   offset 40: pwsz_dark_theme_logo_svg   (ptr, 8)   // optional base64 SVG 1.1
///   offset 48: cb_authenticator_info      (u32, 4)
///   [4 bytes padding for pointer alignment]
///   offset 56: pb_authenticator_info      (ptr, 8)   // CTAP CBOR authenticatorGetInfo
///   offset 64: c_supported_rp_ids         (u32, 4)
///   [4 bytes padding for pointer alignment]
///   offset 72: ppwsz_supported_rp_ids     (ptr, 8)
///   total:     80 bytes
#[repr(C)]
pub struct WebauthnPluginAddAuthenticatorOptions {
    pub pwsz_authenticator_name:   *const u16,
    pub rclsid:                    Guid,
    pub pwsz_plugin_rp_id:         *const u16,
    pub pwsz_light_theme_logo_svg: *const u16,
    pub pwsz_dark_theme_logo_svg:  *const u16,
    pub cb_authenticator_info:     u32,
    pub pb_authenticator_info:     *const u8,
    pub c_supported_rp_ids:        u32,
    pub ppwsz_supported_rp_ids:    *const *const u16,
}

/// Maps to `EXPERIMENTAL_WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE`.
///
/// Contains the operation-signing public key Windows uses to sign
/// `WEBAUTHN_PLUGIN_OPERATION_REQUEST.pbRequestSignature`. The plugin is
/// expected to verify each incoming request signature against this key.
/// For Phase 2.2 we receive + free the response without verifying — any
/// future enforcement by webauthn.dll will surface as dispatch failures.
///
/// x64 layout: { DWORD cbOpSignPubKey; PBYTE pbOpSignPubKey; } = 16 bytes.
#[repr(C)]
pub struct WebauthnPluginAddAuthenticatorResponse {
    pub cb_op_sign_pub_key: u32,
    pub pb_op_sign_pub_key: *mut u8,
}

// ── ABI size assertions ───────────────────────────────────────────────────────

#[cfg(test)]
mod abi_tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn guid_size() {
        // GUID is always 16 bytes on all Windows targets.
        assert_eq!(size_of::<Guid>(), 16);
    }

    #[test]
    fn operation_request_field_offsets() {
        // On x86-64 Windows (LP64), HWND = 8, GUID = 16:
        //   offset 0:  hwnd (8)
        //   offset 8:  transaction_id (16)
        //   offset 24: cb_request_signature (4)
        //   [4 bytes padding to align pointer]
        //   offset 32: pb_request_signature (8)
        //   offset 40: request_type (4 — enum u32)
        //   offset 44: cb_encoded_request (4)
        //   offset 48: pb_encoded_request (8)
        assert_eq!(offset_of!(WebauthNPluginOperationRequest, hwnd), 0);
        assert_eq!(offset_of!(WebauthNPluginOperationRequest, transaction_id), 8);
        // cb_request_signature follows directly after GUID.
        assert_eq!(offset_of!(WebauthNPluginOperationRequest, cb_request_signature), 24);
    }

    #[test]
    fn operation_response_size() {
        // Layout: { DWORD cbEncodedResponse; byte *pbEncodedResponse; }
        // x64: u32(4) + pad(4) + ptr(8) = 16
        // x86: u32(4) + ptr(4) = 8
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size_of::<WebauthNPluginOperationResponse>(), 16);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(size_of::<WebauthNPluginOperationResponse>(), 8);
    }

    #[test]
    fn operation_response_field_offsets() {
        assert_eq!(offset_of!(WebauthNPluginOperationResponse, cb_encoded_response), 0);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(offset_of!(WebauthNPluginOperationResponse, pb_encoded_response), 8);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(offset_of!(WebauthNPluginOperationResponse, pb_encoded_response), 4);
    }

    #[test]
    fn iid_constants_agree() {
        use crate::com::types::IID_IPLUGIN_AUTHENTICATOR;
        // Always assert local constant has expected value:
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data1, 0xd26b_cf6f);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data2, 0xb54c);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data3, 0x43ff);
        assert_eq!(IID_IPLUGIN_AUTHENTICATOR.data4, [0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7]);
        // Windows-only: also verify the From impl produces the same bytes.
        #[cfg(windows)]
        {
            let w: windows::core::GUID = IID_IPLUGIN_AUTHENTICATOR.into();
            assert_eq!(w.data1, IID_IPLUGIN_AUTHENTICATOR.data1);
            assert_eq!(w.data2, IID_IPLUGIN_AUTHENTICATOR.data2);
            assert_eq!(w.data3, IID_IPLUGIN_AUTHENTICATOR.data3);
            assert_eq!(w.data4, IID_IPLUGIN_AUTHENTICATOR.data4);
        }
    }

    #[test]
    fn lock_status_values() {
        assert_eq!(PluginLockStatus::Locked as u32, 0);
        assert_eq!(PluginLockStatus::Unlocked as u32, 1);
    }

    #[test]
    fn request_type_value() {
        assert_eq!(WebauthNPluginRequestType::Ctap2Cbor as u32, 1);
    }

    #[test]
    fn add_authenticator_options_size() {
        // Newer SDK layout (10.0.26100.7175+):
        //   ptr(8) + Guid(16) + 3×ptr(24) + u32(4)+pad(4) + ptr(8) + u32(4)+pad(4) + ptr(8) = 80
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size_of::<WebauthnPluginAddAuthenticatorOptions>(), 80);
    }

    #[test]
    fn add_authenticator_options_field_offsets() {
        assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, pwsz_authenticator_name), 0);
        #[cfg(target_pointer_width = "64")]
        {
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, rclsid),                    8);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, pwsz_plugin_rp_id),         24);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, pwsz_light_theme_logo_svg), 32);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, pwsz_dark_theme_logo_svg),  40);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, cb_authenticator_info),     48);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, pb_authenticator_info),     56);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, c_supported_rp_ids),        64);
            assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorOptions, ppwsz_supported_rp_ids),    72);
        }
    }

    #[test]
    fn add_authenticator_response_size() {
        // Layout: { DWORD cb; PBYTE pb; }
        // x64: u32(4) + pad(4) + ptr(8) = 16. x86: u32(4) + ptr(4) = 8.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size_of::<WebauthnPluginAddAuthenticatorResponse>(), 16);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(size_of::<WebauthnPluginAddAuthenticatorResponse>(), 8);
    }

    #[test]
    fn add_authenticator_response_field_offsets() {
        assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorResponse, cb_op_sign_pub_key), 0);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorResponse, pb_op_sign_pub_key), 8);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(offset_of!(WebauthnPluginAddAuthenticatorResponse, pb_op_sign_pub_key), 4);
    }
}
