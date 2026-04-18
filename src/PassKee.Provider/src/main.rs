//! PassKee Windows Passkey Provider — Phase 2 CLI.
//!
//! Subcommands:
//!   -PluginActivated  -- COM ExeServer activation path (Windows-only, never returns).
//!   register          -- Register PassKee with Windows WebAuthn (Windows-only stub).
//!   unregister        -- Unregister PassKee from Windows WebAuthn (Windows-only stub).
//!   smoke             -- Connect, handshake, print hello response.
//!   make-credential   -- Full makeCredential flow via the plugin pipe.

use passkee_provider::ipc::{self, PipeClient};
use passkee_provider::ctap::{
    self as ctap,
    CreatePasskeyParams, DeleteCredentialParams, ListCredentialsParams,
    SignAssertionParams, rp_id_hash,
};

use std::process;
use tracing_subscriber::fmt;

/// Expected package family name for the sidecar — must match the C# constant.
const PKG_FAMILY: &str = "PassKee.Provider_rh4edrm0by30m";

// ── Subcommand enum (factored out for unit-testability) ───────────────────────

#[derive(Debug, PartialEq)]
enum Subcommand {
    PluginActivated,
    Register,
    Unregister,
    Smoke,
    MakeCredential,
    Unknown,
}

fn parse_subcommand(s: &str) -> Subcommand {
    match s {
        "-PluginActivated" => Subcommand::PluginActivated,
        "register"         => Subcommand::Register,
        "unregister"       => Subcommand::Unregister,
        "smoke"            => Subcommand::Smoke,
        "make-credential"  => Subcommand::MakeCredential,
        _                  => Subcommand::Unknown,
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let sub_str = args.get(1).map(String::as_str).unwrap_or("");
    let sub = parse_subcommand(sub_str);

    let exit_code = match sub {
        Subcommand::PluginActivated => run_plugin_activated(),
        Subcommand::Register        => run_register(),
        Subcommand::Unregister      => run_unregister(),
        Subcommand::Smoke           => run_blocking_async(|| cmd_smoke(&args)),
        Subcommand::MakeCredential  => run_blocking_async(|| cmd_make_credential(&args)),
        Subcommand::Unknown         => { print_usage(); 1 }
    };

    process::exit(exit_code);
}

// ── Platform dispatch: -PluginActivated ──────────────────────────────────────

#[cfg(windows)]
fn run_plugin_activated() -> i32 {
    // run_com_server() has return type `!` — it never returns.
    passkee_provider::com::exe_server::run_com_server()
}

#[cfg(not(windows))]
fn run_plugin_activated() -> i32 {
    eprintln!("-PluginActivated is Windows-only");
    1
}

// ── Platform dispatch: register ──────────────────────────────────────────────

#[cfg(windows)]
fn run_register() -> i32 {
    match passkee_provider::com::exe_server::cmd_register() {
        Ok(()) => 0,
        Err(e) => { eprintln!("register failed: {e}"); 1 }
    }
}

#[cfg(not(windows))]
fn run_register() -> i32 {
    eprintln!("register is Windows-only");
    1
}

// ── Platform dispatch: unregister ────────────────────────────────────────────

#[cfg(windows)]
fn run_unregister() -> i32 {
    match passkee_provider::com::exe_server::cmd_unregister() {
        Ok(()) => 0,
        Err(e) => { eprintln!("unregister failed: {e}"); 1 }
    }
}

#[cfg(not(windows))]
fn run_unregister() -> i32 {
    eprintln!("unregister is Windows-only");
    1
}

// ── Async runner (smoke / make-credential) ───────────────────────────────────

fn run_blocking_async<F, Fut>(f: F) -> i32
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tokio runtime init failed: {e}");
            return 1;
        }
    };
    match rt.block_on(f()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ── Subcommand implementations ────────────────────────────────────────────────

async fn cmd_smoke(args: &[String]) -> Result<(), String> {
    let (session_id, nonce) = parse_session_nonce(args);

    eprintln!("[smoke] Connecting to pipe PassKee.{session_id}...");
    let mut client = PipeClient::connect(session_id).await
        .map_err(|e| format!("connect failed: {e}"))?;
    eprintln!("[smoke] Connected. Performing handshake...");
    client.handshake(PKG_FAMILY, &nonce).await
        .map_err(|e| format!("handshake failed: {e}"))?;
    eprintln!("[smoke] Handshake OK. Plugin is live.");
    Ok(())
}

async fn cmd_make_credential(args: &[String]) -> Result<(), String> {
    let (session_id, nonce) = parse_session_nonce(args);
    let rp_id = flag(args, "--rp-id").unwrap_or_else(|| "example.com".into());
    let user = flag(args, "--user").unwrap_or_else(|| "user@example.com".into());

    eprintln!("[make-credential] Connecting to pipe PassKee.{session_id}...");
    let mut client = PipeClient::connect(session_id).await
        .map_err(|e| format!("connect failed: {e}"))?;
    client.handshake(PKG_FAMILY, &nonce).await
        .map_err(|e| format!("handshake failed: {e}"))?;
    eprintln!("[make-credential] Handshake OK.");

    let params = CreatePasskeyParams {
        rp_id: rp_id.clone(),
        rp_name: rp_id.clone(),
        user_handle: base64_encode(b"test-user-handle"),
        user_name: user.clone(),
        user_display_name: user.clone(),
    };

    let result: ctap::CreatePasskeyResult = client.call("passkee.createPasskey", &params).await
        .map_err(|e| format!("createPasskey failed: {e}"))?;
    eprintln!("[make-credential] Created credential: {}", result.credential_id);

    // Verify the rpIdHash in authData.
    let auth_data = base64_decode(&result.auth_data);
    if auth_data.len() >= 32 {
        let expected = rp_id_hash(&rp_id);
        if auth_data[..32] == expected {
            eprintln!("[make-credential] rpIdHash in authData: OK");
        } else {
            eprintln!("[make-credential] WARNING: rpIdHash mismatch in authData");
        }
    }

    // List credentials.
    let creds: Vec<ctap::CredentialInfo> = client
        .call(
            "passkee.listCredentials",
            ListCredentialsParams { rp_id: rp_id.clone() },
        )
        .await
        .map_err(|e| format!("listCredentials failed: {e}"))?;
    eprintln!("[make-credential] listCredentials returned {} entry/entries", creds.len());

    // Sign an assertion.
    let auth_data_bytes = vec![0u8; 37];
    let client_data_hash = sha2_hash(b"{\"type\":\"webauthn.get\",\"challenge\":\"dGVzdA\"}");
    let sign_params = SignAssertionParams {
        credential_id: result.credential_id.clone(),
        auth_data: base64_encode(&auth_data_bytes),
        client_data_hash: base64_encode(&client_data_hash),
    };
    let sig: ctap::SignAssertionResult = client.call("passkee.signAssertion", &sign_params).await
        .map_err(|e| format!("signAssertion failed: {e}"))?;
    eprintln!(
        "[make-credential] Signature ({} bytes): OK",
        base64_decode(&sig.signature).len()
    );

    // Delete the credential.
    let del: ctap::DeleteCredentialResult = client
        .call(
            "passkee.deleteCredential",
            DeleteCredentialParams { credential_id: result.credential_id },
        )
        .await
        .map_err(|e| format!("deleteCredential failed: {e}"))?;
    eprintln!("[make-credential] deleteCredential: deleted={}", del.deleted);

    eprintln!("[make-credential] All steps PASSED.");
    Ok(())
}

// ── Usage banner ──────────────────────────────────────────────────────────────

fn print_usage() {
    eprintln!("Usage: passkee-provider <subcommand> [options]");
    eprintln!();
    eprintln!("Subcommands:");
    eprintln!("  -PluginActivated              Run as COM ExeServer (Windows-only; launched by the OS)");
    eprintln!("  register                      Register PassKee with Windows WebAuthn (Windows-only)");
    eprintln!("  unregister                    Unregister PassKee from Windows WebAuthn (Windows-only)");
    eprintln!("  smoke     --session <id> --nonce <nonce>                  Handshake smoke test");
    eprintln!("  make-credential --session <id> --nonce <nonce> --rp-id <x> --user <y>");
    eprintln!("                                Full makeCredential IPC flow");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_session_nonce(args: &[String]) -> (u32, String) {
    let session_id: u32 = flag(args, "--session")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let nonce = flag(args, "--nonce").unwrap_or_else(|| {
        #[cfg(windows)]
        {
            read_nonce_from_registry().unwrap_or_else(|| {
                eprintln!("ERROR: --nonce required (registry read failed)");
                process::exit(1);
            })
        }
        #[cfg(not(windows))]
        {
            eprintln!("ERROR: --nonce is required on non-Windows");
            process::exit(1);
        }
    });
    (session_id, nonce)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(windows)]
fn read_nonce_from_registry() -> Option<String> {
    // HKCU\Software\PassKee\HandshakeNonce — written by the plugin on Initialize().
    use windows::Win32::System::Registry::{
        RegCloseKey, RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ,
    };
    use windows::core::PCWSTR;

    let sub_key: Vec<u16> = "Software\\PassKee\0".encode_utf16().collect();
    let value_name: Vec<u16> = "HandshakeNonce\0".encode_utf16().collect();
    let mut buf = vec![0u16; 256];
    let mut buf_bytes = (buf.len() * 2) as u32;
    let mut hkey = windows::Win32::System::Registry::HKEY::default();

    let rc = unsafe {
        windows::Win32::System::Registry::RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(sub_key.as_ptr()),
            Some(0),
            windows::Win32::System::Registry::KEY_READ,
            &mut hkey,
        )
    };
    if rc.is_err() { return None; }

    let rc = unsafe {
        RegGetValueW(
            hkey,
            PCWSTR::null(),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr() as *mut _),
            Some(&mut buf_bytes),
        )
    };
    let _ = unsafe { RegCloseKey(hkey) };
    if rc.is_err() { return None; }

    // buf_bytes includes the null terminator; convert to String.
    let len = (buf_bytes / 2).saturating_sub(1) as usize;
    Some(String::from_utf16_lossy(&buf[..len]))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plugin_activated() {
        assert_eq!(parse_subcommand("-PluginActivated"), Subcommand::PluginActivated);
    }

    #[test]
    fn parse_register() {
        assert_eq!(parse_subcommand("register"), Subcommand::Register);
    }

    #[test]
    fn parse_unregister() {
        assert_eq!(parse_subcommand("unregister"), Subcommand::Unregister);
    }

    #[test]
    fn parse_smoke() {
        assert_eq!(parse_subcommand("smoke"), Subcommand::Smoke);
    }

    #[test]
    fn parse_make_credential() {
        assert_eq!(parse_subcommand("make-credential"), Subcommand::MakeCredential);
    }

    #[test]
    fn parse_empty_is_unknown() {
        assert_eq!(parse_subcommand(""), Subcommand::Unknown);
    }

    #[test]
    fn parse_garbage_is_unknown() {
        assert_eq!(parse_subcommand("garbage"), Subcommand::Unknown);
    }

    #[test]
    fn parse_case_sensitive() {
        // Must not match with different casing.
        assert_eq!(parse_subcommand("Smoke"), Subcommand::Unknown);
        assert_eq!(parse_subcommand("REGISTER"), Subcommand::Unknown);
    }
}
