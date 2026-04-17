//! PassKee Windows Passkey Provider — Phase 2 prep CLI.
//!
//! Subcommands:
//!   smoke            -- connect, handshake, print hello response.
//!   make-credential  -- full makeCredential flow via the plugin pipe.

use passkee_provider::ipc::{self, PipeClient};
use passkee_provider::ctap::{
    self as ctap,
    CreatePasskeyParams, DeleteCredentialParams, ListCredentialsParams,
    SignAssertionParams, rp_id_hash,
};

use std::process;
use tracing_subscriber::fmt;

/// Expected package family name for the sidecar — must match the C# constant.
const PKG_FAMILY: &str = "PassKee.Provider_8wekyb3d8bbwe";

#[tokio::main]
async fn main() {
    fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: passkee-provider <smoke|make-credential> [options]");
        eprintln!("  smoke --session <id> --nonce <nonce>");
        eprintln!("  make-credential --session <id> --nonce <nonce> --rp-id <x> --user <y>");
        process::exit(1);
    }

    let result = match args[1].as_str() {
        "smoke" => cmd_smoke(&args[2..]).await,
        "make-credential" => cmd_make_credential(&args[2..]).await,
        other => {
            eprintln!("Unknown subcommand: {other}");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

async fn cmd_smoke(args: &[String]) -> Result<(), ipc::ClientError> {
    let (session_id, nonce) = parse_session_nonce(args);

    eprintln!("[smoke] Connecting to pipe PassKee.{session_id}...");
    let mut client = PipeClient::connect(session_id).await?;
    eprintln!("[smoke] Connected. Performing handshake...");
    client.handshake(PKG_FAMILY, &nonce).await?;
    eprintln!("[smoke] Handshake OK. Plugin is live.");
    Ok(())
}

async fn cmd_make_credential(args: &[String]) -> Result<(), ipc::ClientError> {
    let (session_id, nonce) = parse_session_nonce(args);
    let rp_id = flag(args, "--rp-id").unwrap_or_else(|| "example.com".into());
    let user = flag(args, "--user").unwrap_or_else(|| "user@example.com".into());

    eprintln!("[make-credential] Connecting to pipe PassKee.{session_id}...");
    let mut client = PipeClient::connect(session_id).await?;
    client.handshake(PKG_FAMILY, &nonce).await?;
    eprintln!("[make-credential] Handshake OK.");

    let params = CreatePasskeyParams {
        rp_id: rp_id.clone(),
        rp_name: rp_id.clone(),
        user_handle: base64_encode(b"test-user-handle"),
        user_name: user.clone(),
        user_display_name: user.clone(),
    };

    let result: ctap::CreatePasskeyResult = client.call("passkee.createPasskey", &params).await?;
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
        .await?;
    eprintln!("[make-credential] listCredentials returned {} entry/entries", creds.len());

    // Sign an assertion.
    let auth_data_bytes = vec![0u8; 37];
    let client_data_hash = sha2_hash(b"{\"type\":\"webauthn.get\",\"challenge\":\"dGVzdA\"}");
    let sign_params = SignAssertionParams {
        credential_id: result.credential_id.clone(),
        auth_data: base64_encode(&auth_data_bytes),
        client_data_hash: base64_encode(&client_data_hash),
    };
    let sig: ctap::SignAssertionResult = client.call("passkee.signAssertion", &sign_params).await?;
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
        .await?;
    eprintln!("[make-credential] deleteCredential: deleted={}", del.deleted);

    eprintln!("[make-credential] All steps PASSED.");
    Ok(())
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
