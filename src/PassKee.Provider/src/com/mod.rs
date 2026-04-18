//! COM bindings for IPluginAuthenticator.
//!
//! Microsoft's win32metadata does not yet include IPluginAuthenticator, so we
//! hand-roll the interface declaration using `windows::core` primitives. The
//! vtable layout and IID come directly from
//! `idl/pluginauthenticator.h` (MIDL-generated, from microsoft/webauthn).
//!
//! IID: {d26bcf6f-b54c-43ff-9f06-d5bf148625f7}
//! Methods (after IUnknown):
//!   0  MakeCredential(request: PCWEBAUTHN_PLUGIN_OPERATION_REQUEST,
//!                     response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE) -> HRESULT
//!   1  GetAssertion(request: PCWEBAUTHN_PLUGIN_OPERATION_REQUEST,
//!                   response: *mut WEBAUTHN_PLUGIN_OPERATION_RESPONSE) -> HRESULT
//!   2  CancelOperation(request: PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST) -> HRESULT
//!   3  GetLockStatus(lock_status: *mut PluginLockStatus) -> HRESULT

pub mod server;
#[cfg(windows)]
pub mod exe_server;
pub mod types;
