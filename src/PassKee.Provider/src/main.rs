//! PassKee Windows Passkey Provider
//!
//! MSIX-packaged COM server implementing Windows' `IPluginAuthenticator`.
//! Bridges `MakeCredential` / `GetAssertion` operations to the PassKee
//! KeePass 2.x plugin over a named pipe.
//!
//! Phase 0 scaffolding. Nothing is wired up yet.

fn main() {
    eprintln!("PassKee.Provider — Phase 0 stub. Not yet implemented.");
    std::process::exit(1);
}
