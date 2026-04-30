//! CTAP2 request/response types for the plugin JSON-RPC wire format.
//!
//! Contains the serialisable structs used for keepasskeywin.* RPC calls, plus
//! the `rp_id_hash` helper. The heavy CTAP2 parsing happens in the C# plugin
//! (VaultHandler) or the Windows-only COM dispatch (com::server); this module
//! only covers the types the CLI sidecar needs to construct and consume.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Plugin JSON-RPC param/result types ──────────────────────────────────────

/// Params for `keepasskeywin.createPasskey` RPC call.
#[derive(Debug, Serialize)]
pub struct CreatePasskeyParams {
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "rpName")]
    pub rp_name: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "userDisplayName")]
    pub user_display_name: String,
}

/// Result from `keepasskeywin.createPasskey` RPC call.
#[derive(Debug, Deserialize)]
pub struct CreatePasskeyResult {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "publicKeyCose")]
    pub public_key_cose: String,
    #[serde(rename = "authData")]
    pub auth_data: String,
}

/// Params for `keepasskeywin.signAssertion` RPC call.
#[derive(Debug, Serialize)]
pub struct SignAssertionParams {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "authData")]
    pub auth_data: String,
    #[serde(rename = "clientDataHash")]
    pub client_data_hash: String,
}

/// Result from `keepasskeywin.signAssertion` RPC call.
#[derive(Debug, Deserialize)]
pub struct SignAssertionResult {
    #[serde(rename = "signature")]
    pub signature: String,
}

/// Params for `keepasskeywin.listCredentials` RPC call.
#[derive(Debug, Serialize)]
pub struct ListCredentialsParams {
    #[serde(rename = "rpId")]
    pub rp_id: String,
}

/// Single credential entry returned by `keepasskeywin.listCredentials`.
#[derive(Debug, Deserialize)]
pub struct CredentialInfo {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "rpId")]
    pub rp_id: String,
}

/// Params for `keepasskeywin.deleteCredential` RPC call.
#[derive(Debug, Serialize)]
pub struct DeleteCredentialParams {
    #[serde(rename = "credentialId")]
    pub credential_id: String,
}

/// Result from `keepasskeywin.deleteCredential` RPC call.
#[derive(Debug, Deserialize)]
pub struct DeleteCredentialResult {
    pub deleted: bool,
}

// ── rpIdHash helper ───────────────────────────────────────────────────────────

/// Returns SHA-256 of the RP ID, as required for authenticatorData construction.
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    hasher.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_id_hash_known_value() {
        // SHA-256("webauthn.io") as hex.
        let hash = rp_id_hash("webauthn.io");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        // Verified with: echo -n "webauthn.io" | sha256sum
        assert_eq!(
            hex,
            "74a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef0"
        );
    }

    #[test]
    fn create_passkey_params_serialize() {
        let p = CreatePasskeyParams {
            rp_id: "example.com".into(),
            rp_name: "Example".into(),
            user_handle: "dXNlcg==".into(),
            user_name: "user@example.com".into(),
            user_display_name: "Test User".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"rpId\":\"example.com\""));
        assert!(json.contains("\"rpName\":\"Example\""));
        assert!(json.contains("\"userHandle\":\"dXNlcg==\""));
    }

    #[test]
    fn create_passkey_result_deserialize() {
        let json = r#"{"credentialId":"abc123","publicKeyCose":"cose==","authData":"auth=="}"#;
        let r: CreatePasskeyResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.credential_id, "abc123");
        assert_eq!(r.public_key_cose, "cose==");
    }

    #[test]
    fn sign_assertion_params_serialize() {
        let p = SignAssertionParams {
            credential_id: "cred1".into(),
            auth_data: "auth==".into(),
            client_data_hash: "hash==".into(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"credentialId\":\"cred1\""));
        assert!(json.contains("\"authData\":\"auth==\""));
        assert!(json.contains("\"clientDataHash\":\"hash==\""));
    }

    #[test]
    fn sign_assertion_result_deserialize() {
        let json = r#"{"signature":"sig=="}"#;
        let r: SignAssertionResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.signature, "sig==");
    }

    #[test]
    fn list_credentials_result_deserialize() {
        let json = r#"[{"credentialId":"c1","userName":"u1","rpId":"rp1"}]"#;
        let creds: Vec<CredentialInfo> = serde_json::from_str(json).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].credential_id, "c1");
    }

    #[test]
    fn delete_credential_result_deserialize() {
        let json = r#"{"deleted":true}"#;
        let r: DeleteCredentialResult = serde_json::from_str(json).unwrap();
        assert!(r.deleted);
    }
}
