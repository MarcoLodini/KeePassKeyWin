//! JSON-RPC 2.0 client over a named pipe (Windows) or Unix socket (Linux test fallback).
//!
//! Protocol: line-delimited JSON, one request per line, one response per line.
//! See docs/IPC_PROTOCOL.md for the full spec.

use std::time::Duration;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("connection timed out after 5s")]
    Timeout,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vault is locked or closed")]
    VaultLocked,
    #[error("credential not found")]
    NoCredentials,
    #[error("handshake required or invalid")]
    ClientUnauthorized,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("credential already registered")]
    CredentialExcluded,
    #[error("unsupported option (e.g. options.up=false)")]
    InvalidOption,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("internal server error: {0}")]
    Internal(String),
    #[error("unknown RPC error {code}: {message}")]
    RpcError { code: i32, message: String },
}

impl ClientError {
    fn from_rpc(code: i32, message: String) -> Self {
        match code {
            -32010 => ClientError::VaultLocked,
            -32020 => ClientError::NoCredentials,
            -32030 => ClientError::UnsupportedAlgorithm,
            -32031 => ClientError::CredentialExcluded,
            -32041 => ClientError::InvalidOption,
            -32000 | -32001 => ClientError::ClientUnauthorized,
            -32600 | -32602 => ClientError::InvalidRequest(message),
            -32603 => ClientError::Internal(message),
            _ => ClientError::RpcError { code, message },
        }
    }
}

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'static str,
    id: u32,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(rename = "id")]
    _id: serde_json::Value,
    result: Option<serde_json::Value>,
    error: Option<RpcErrorObj>,
}

#[derive(Deserialize)]
struct RpcErrorObj {
    code: i32,
    message: String,
}

// ── Platform transport ───────────────────────────────────────────────────────

/// Wraps the platform-specific read/write halves behind a uniform async interface.
struct Transport {
    reader: BufReader<Box<dyn tokio::io::AsyncRead + Unpin + Send>>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
}

impl Transport {
    async fn send_line(&mut self, line: &str) -> std::io::Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        self.writer.flush().await
    }

    async fn recv_line(&mut self) -> std::io::Result<String> {
        let mut buf = String::new();
        self.reader.read_line(&mut buf).await?;
        if buf.ends_with('\n') {
            buf.pop();
        }
        Ok(buf)
    }
}

// ── PipeClient ───────────────────────────────────────────────────────────────

/// Async JSON-RPC 2.0 client.
/// On Windows: connects to `\\.\pipe\KeePassKeyWin.<session_id>`.
/// On Unix: connects to `/tmp/keepasskeywin-test-<session_id>.sock` (test only).
pub struct PipeClient {
    transport: Transport,
    next_id: u32,
}

impl PipeClient {
    /// Connect with exponential back-off, total budget ~5 s.
    pub async fn connect(session_id: u32) -> Result<Self, ClientError> {
        let delays_ms: &[u64] = &[50, 100, 200, 400, 800, 1600, 1850];
        let mut last_err = None;

        for &delay in delays_ms {
            match Self::try_connect(session_id).await {
                Ok(client) => return Ok(client),
                Err(e) => {
                    debug!("connect attempt failed: {e}, retrying in {delay}ms");
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }

        // One final attempt after the last sleep.
        Self::try_connect(session_id).await.map_err(|_| {
            last_err.unwrap_or(ClientError::Timeout)
        })
    }

    async fn try_connect(session_id: u32) -> Result<Self, ClientError> {
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            let pipe_name = format!(r"\\.\pipe\KeePassKeyWin.{session_id}");
            let pipe = ClientOptions::new().open(&pipe_name)?;
            let (read_half, write_half) = tokio::io::split(pipe);
            let transport = Transport {
                reader: BufReader::new(Box::new(read_half)),
                writer: Box::new(write_half),
            };
            Ok(PipeClient { transport, next_id: 1 })
        }
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;
            let path = format!("/tmp/keepasskeywin-test-{session_id}.sock");
            let stream = UnixStream::connect(&path).await?;
            let (read_half, write_half) = stream.into_split();
            let transport = Transport {
                reader: BufReader::new(Box::new(read_half)),
                writer: Box::new(write_half),
            };
            Ok(PipeClient { transport, next_id: 1 })
        }
    }

    /// Send `keepasskeywin.hello` with the given package family name, nonce,
    /// and op-signing public key bytes.
    ///
    /// Since 5.UV.4, `opSignPublicKeyB64` is **required** by the plugin —
    /// without it, UV signature verification cannot run and the plugin rejects
    /// the hello. If `pub_key_bytes` is `None` (key-fetch failed), we return
    /// `Err` here rather than letting the plugin reject a malformed hello later.
    ///
    /// In production, callers pass `get_op_sign_pub_key_bytes_for_hello()`.
    /// Tests may inject `None` to exercise this error path without needing
    /// a real Windows CNG key store.
    pub async fn handshake(
        &mut self,
        client_pkg_family: &str,
        nonce: &str,
        pub_key_bytes: Option<Vec<u8>>,
    ) -> Result<(), ClientError> {
        use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

        #[derive(Serialize)]
        struct HelloParams<'a> {
            #[serde(rename = "clientPkgFamilyName")]
            client_pkg_family_name: &'a str,
            #[serde(rename = "handshakeNonce")]
            handshake_nonce: &'a str,
            /// Op-signing public key bytes (BCRYPT_PUBLIC_KEY_BLOB), base64-std encoded.
            /// Required since 5.UV.4 — plugin rejects hello without this field.
            #[serde(rename = "opSignPublicKeyB64")]
            op_sign_public_key_b64: String,
        }

        let key_bytes = pub_key_bytes.ok_or_else(|| {
            ClientError::InvalidRequest(
                "op-sign public key unavailable — cannot complete handshake without it".to_string()
            )
        })?;

        let op_sign_public_key_b64 = BASE64_STANDARD.encode(&key_bytes);

        let _: serde_json::Value = self
            .call(
                "keepasskeywin.hello",
                HelloParams {
                    client_pkg_family_name: client_pkg_family,
                    handshake_nonce: nonce,
                    op_sign_public_key_b64,
                },
            )
            .await?;
        Ok(())
    }

    /// Generic JSON-RPC call. Returns the `result` field deserialized as `R`.
    pub async fn call<R, P>(&mut self, method: &str, params: P) -> Result<R, ClientError>
    where
        R: DeserializeOwned,
        P: Serialize,
    {
        let id = self.next_id;
        self.next_id += 1;

        let request = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };

        let line = serde_json::to_string(&request)?;
        debug!(method, id, "→ RPC request");
        self.transport.send_line(&line).await?;

        let resp_line = self.transport.recv_line().await?;
        debug!(method, id, "← RPC response");

        let response: RpcResponse = serde_json::from_str(&resp_line)?;

        if let Some(err) = response.error {
            return Err(ClientError::from_rpc(err.code, err.message));
        }

        let result = response.result.unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(result)?)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_mapping_vault_locked() {
        let e = ClientError::from_rpc(-32010, "locked".into());
        assert!(matches!(e, ClientError::VaultLocked));
    }

    #[test]
    fn error_mapping_no_credentials() {
        let e = ClientError::from_rpc(-32020, "not found".into());
        assert!(matches!(e, ClientError::NoCredentials));
    }

    #[test]
    fn error_mapping_unauthorized() {
        let e = ClientError::from_rpc(-32001, "bad nonce".into());
        assert!(matches!(e, ClientError::ClientUnauthorized));
    }

    #[test]
    fn error_mapping_unknown() {
        let e = ClientError::from_rpc(-99, "custom".into());
        assert!(matches!(e, ClientError::RpcError { code: -99, .. }));
    }

    #[test]
    fn error_mapping_unsupported_algorithm() {
        let e = ClientError::from_rpc(-32030, "alg not supported".into());
        assert!(matches!(e, ClientError::UnsupportedAlgorithm));
    }

    #[test]
    fn error_mapping_credential_excluded() {
        let e = ClientError::from_rpc(-32031, "already registered".into());
        assert!(matches!(e, ClientError::CredentialExcluded));
    }

    #[test]
    fn error_mapping_invalid_option() {
        let e = ClientError::from_rpc(-32041, "options.up=false not supported".into());
        assert!(matches!(e, ClientError::InvalidOption));
    }

    #[test]
    fn rpc_request_serializes_correctly() {
        #[derive(Serialize)]
        struct P {
            x: u32,
        }
        let req = RpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "test.method",
            params: P { x: 42 },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"test.method\""));
        assert!(json.contains("\"x\":42"));
    }

    /// 5.UV.4: handshake() returns Err(InvalidRequest) when pub_key_bytes is None.
    /// The error fires before any network I/O, so no server is needed.
    #[tokio::test]
    async fn handshake_none_pubkey_returns_err() {
        use tokio::io::duplex;
        use tokio::io::{split, AsyncWriteExt};

        // Create a dummy pipe so PipeClient can be constructed, but we never
        // actually read from it — the error fires before the hello is sent.
        let (client_io, mut server_io) = duplex(4096);
        let (read_half, write_half) = split(client_io);
        let transport = Transport {
            reader: tokio::io::BufReader::new(Box::new(read_half)),
            writer: Box::new(write_half),
        };
        let mut client = PipeClient { transport, next_id: 1 };

        // Spawn a task to drain server side so the client doesn't block on writes.
        tokio::spawn(async move {
            let _ = server_io.shutdown().await;
        });

        let result = client
            .handshake("KeePassKeyWin.Provider_4fv17arhjxxvg", "test-nonce", None)
            .await;

        assert!(result.is_err(), "expected Err when pub_key_bytes is None");
        match result.unwrap_err() {
            ClientError::InvalidRequest(msg) => {
                assert!(msg.contains("op-sign public key"), "unexpected message: {msg}");
            }
            other => panic!("expected ClientError::InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn rpc_response_ok_deserializes() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":"ok"}"#;
        let r: RpcResponse = serde_json::from_str(json).unwrap();
        assert!(r.error.is_none());
        assert_eq!(r.result.unwrap(), "ok");
    }

    #[test]
    fn rpc_response_error_deserializes() {
        let json = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"locked"}}"#;
        let r: RpcResponse = serde_json::from_str(json).unwrap();
        assert!(r.result.is_none());
        let e = r.error.unwrap();
        assert_eq!(e.code, -32010);
        assert_eq!(e.message, "locked");
    }

    /// 5.UV.8 stale-pipe retry shape: server closes the connection mid-RPC,
    /// client reconnects, retry RPC completes. Covers the load-bearing
    /// "drop dead pipe → reconnect → rerun call" chain that the Windows-only
    /// `server::take_call_with_retry` helper relies on.
    ///
    /// Notes on what this test does and does NOT cover:
    /// * NOT covered: the production helper itself (Windows-only — needs
    ///   `sta_block_on`, `SHARED_STATE`, `connect_and_handshake`'s registry
    ///   nonce read). Those are exercised at integration level on Windows
    ///   via `validate-phase2.ps1` § Step 6c live-validation.
    /// * NOT covered: the `BrokenPipe` error kind itself — Linux's tokio
    ///   UnixStream produces a different error shape for peer-close (often
    ///   `Ok("")` from `read_line`, leading to `ClientError::Json` from the
    ///   empty-string parse, rather than `Io(BrokenPipe)`). Classification
    ///   is unit-tested via synthetic `io::Error::new` in
    ///   `crate::com::classify_rpc_error::tests`.
    /// * IS covered: the assumption that two `PipeClient::connect` calls in
    ///   the same process succeed (the second one against a fresh server
    ///   instance), and the second client's `call` returns a valid response.
    ///   If Linux's peer-close handling ever stops being recoverable by a
    ///   second connect, this test catches it.
    #[cfg(unix)]
    #[tokio::test]
    async fn stale_pipe_reconnect_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let session_id: u32 = 55556;
        let sock_path = format!("/tmp/keepasskeywin-test-{session_id}.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();

        tokio::spawn(async move {
            // Connection 1: accept, read first request, drop the stream
            // without responding. The client's recv_line returns
            // `Ok("")` once EOF is observed; the empty-string parse then
            // surfaces as `ClientError::Json`.
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = s1.read(&mut buf).await.unwrap();
            drop(s1);

            // Connection 2: accept, read, send a happy "retry succeeded"
            // response. Mirrors what the production retry path expects after
            // a successful reconnect+rehandshake on Windows.
            let (mut s2, _) = listener.accept().await.unwrap();
            buf.fill(0);
            let n = s2.read(&mut buf).await.unwrap();
            let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
            let id = &req["id"];
            let resp = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"retry_succeeded\":true}}}}\n"
            );
            s2.write_all(resp.as_bytes()).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(20)).await;

        // First call: expected to fail (server dropped without responding).
        let mut client1 = PipeClient::connect(session_id)
            .await
            .expect("first connect must succeed");
        let result1: Result<serde_json::Value, ClientError> = client1
            .call("test.method", serde_json::json!({"x": 1}))
            .await;
        assert!(
            result1.is_err(),
            "first call must fail after server-side drop, got: {result1:?}",
        );

        // Drop the dead client, reconnect to the listener (which is still
        // alive in the spawned task — its second accept() is waiting).
        drop(client1);
        let mut client2 = PipeClient::connect(session_id)
            .await
            .expect("second connect must succeed — load-bearing for stale-pipe retry");
        let result2: serde_json::Value = client2
            .call("test.method", serde_json::json!({"x": 1}))
            .await
            .expect("retry call must succeed on fresh connection");
        assert_eq!(
            result2["retry_succeeded"], true,
            "fresh connection must serve retry round-trip cleanly",
        );

        let _ = std::fs::remove_file(&sock_path);
    }

    /// Unix-socket round-trip test: spins up a tiny JSON-RPC echo server,
    /// connects PipeClient, performs handshake, and calls a method.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_pipe_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let session_id: u32 = 55555;
        let sock_path = format!("/tmp/keepasskeywin-test-{session_id}.sock");
        let _ = std::fs::remove_file(&sock_path);

        let listener = UnixListener::bind(&sock_path).unwrap();

        // Server task: echo a canned handshake response then one RPC response.
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];

            // Read hello request.
            let n = stream.read(&mut buf).await.unwrap();
            let _hello: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();

            // Send hello ok.
            stream
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n")
                .await
                .unwrap();

            // Read second request.
            buf.fill(0);
            let n = stream.read(&mut buf).await.unwrap();
            let req: serde_json::Value = serde_json::from_slice(&buf[..n]).unwrap();
            let id = &req["id"];

            // Echo back a result.
            let resp = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"echo\":true}}}}\n"
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        });

        // Give the server a moment to start listening.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut client = PipeClient::connect(session_id).await.unwrap();
        // In this test the server echoes any hello response as "ok", so the
        // pub_key_bytes content does not matter — use a dummy 72-byte blob.
        let dummy_key = Some(vec![0u8; 72]);
        client
            .handshake("KeePassKeyWin.Provider_4fv17arhjxxvg", "deadbeef", dummy_key)
            .await
            .unwrap();

        let result: serde_json::Value = client
            .call("keepasskeywin.listCredentials", serde_json::json!({"rpId": "example.com"}))
            .await
            .unwrap();

        assert_eq!(result["echo"], true);

        let _ = std::fs::remove_file(&sock_path);
    }
}
