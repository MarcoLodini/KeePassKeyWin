//! KeePassKeyWin Provider — library root.
//!
//! On Windows: exposes the COM EXE-server (ClassFactory, run_com_server,
//! cmd_register, cmd_unregister) and the full IPluginAuthenticator COM server.
//! On Linux: compiles the shared IPC/CTAP modules + pure-Rust COM type stubs
//! so that non-runtime tests (ABI assertions, serde round-trips) run on CI.

pub mod ctap;
pub mod ipc;

// COM module — types always available; implementation Windows-only.
pub mod com {
    // Pure Rust repr(C) structs — compile everywhere for test coverage.
    pub mod types;
    // Cross-platform: CTAP2 authenticatorGetInfo CBOR blob + AAGUID constant.
    // Consumed by exe_server::cmd_register on Windows; covered by Linux CI tests.
    pub mod authenticator_info;
    // Server implementation — imports windows-rs, Windows only.
    #[cfg(windows)]
    pub mod server;
    // EXE-server entry points (ClassFactory, run_com_server, cmd_register, cmd_unregister).
    #[cfg(windows)]
    pub mod exe_server;
    // Manual FFI bindings for EXPERIMENTAL_WebAuthNPlugin* registration APIs
    // (not in windows-rs 0.61). Used by exe_server::cmd_register / cmd_unregister.
    #[cfg(windows)]
    pub mod webauthn_ext;
    // Manual FFI bindings for WebAuthNPluginAuthenticator* credential-management
    // APIs (not in windows-rs 0.61). Used by server::dispatch_operation's
    // post-MakeCredential hook to publish credentials into Windows' autofill DB.
    #[cfg(windows)]
    pub mod webauthnplugin_ext;
    // Request-signature verification: fetches the op-signing public key from
    // webauthn.dll (once per process) and verifies pbRequestSignature on every
    // MakeCredential, GetAssertion, and CancelOperation call.
    // The module itself is cross-platform (tests run on Linux); Windows-only
    // code is gated internally with #[cfg(windows)].
    pub mod request_sig;
    // Debug-only override for the PerformUserVerification binding lookup.
    // Cross-platform (tests run on Linux). Read by webauthn_ext::bindings().
    pub mod uv_override;
    // 5.UV.7 v2→v1 call-time fallback decision helpers + cache mutation.
    // Cross-platform (tests run on Linux). Imported by webauthn_ext::perform_user_verification_2.
    pub mod uv_fallback;
    // Non-Windows stub so tests that reference com::server still compile.
    #[cfg(not(windows))]
    pub mod server;
}
