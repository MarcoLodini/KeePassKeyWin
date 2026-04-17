//! PassKee Provider — library root.
//!
//! On Windows: exports COM DLL entry points and the full COM server.
//! On Linux: compiles the shared IPC/CTAP modules + pure-Rust COM type stubs
//! so that non-runtime tests (ABI assertions, serde round-trips) run on CI.

pub mod ctap;
pub mod ipc;

// COM module — types always available; implementation Windows-only.
pub mod com {
    // Pure Rust repr(C) structs — compile everywhere for test coverage.
    pub mod types;
    // Server implementation — imports windows-rs, Windows only.
    #[cfg(windows)]
    pub mod server;
    // DLL exports — Windows only.
    #[cfg(windows)]
    pub mod dll;
    // Non-Windows stub so tests that reference com::server still compile.
    #[cfg(not(windows))]
    pub mod server;
}

#[cfg(windows)]
pub use com::dll::*;
