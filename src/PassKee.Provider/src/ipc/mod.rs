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
    #[allow(dead_code)]
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[allow(dead_code)]
    #[error("credential already registered")]
    CredentialExcluded,
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
    #[allow(dead_code)]
    id: serde_json::Value,
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
/// On Windows: connects to `\\.\pipe\PassKee.<session_id>`.
/// On Unix: connects to `/tmp/passkee-test-<session_id>.sock` (test only).
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
            let pipe_name = format!(r"\\.\pipe\PassKee.{session_id}");
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
            let path = format!("/tmp/passkee-test-{session_id}.sock");
            let stream = UnixStream::connect(&path).await?;
            let (read_half, write_half) = stream.into_split();
            let transport = Transport {
                reader: BufReader::new(Box::new(read_half)),
                writer: Box::new(write_half),
            };
            Ok(PipeClient { transport, next_id: 1 })
        }
    }

    /// Send `passkee.hello` with the given package family name and nonce.
    pub async fn handshake(
        &mut self,
        client_pkg_family: &str,
        nonce: &str,
    ) -> Result<(), ClientError> {
        #[derive(Serialize)]
        struct HelloParams<'a> {
            #[serde(rename = "clientPkgFamilyName")]
            client_pkg_family_name: &'a str,
            #[serde(rename = "handshakeNonce")]
            handshake_nonce: &'a str,
        }

        let _: serde_json::Value = self
            .call(
                "passkee.hello",
                HelloParams {
                    client_pkg_family_name: client_pkg_family,
                    handshake_nonce: nonce,
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

    /// Unix-socket round-trip test: spins up a tiny JSON-RPC echo server,
    /// connects PipeClient, performs handshake, and calls a method.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_pipe_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixListener;

        let session_id: u32 = 55555;
        let sock_path = format!("/tmp/passkee-test-{session_id}.sock");
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
        client
            .handshake("PassKee.Provider_rh4edrm0by30m", "deadbeef")
            .await
            .unwrap();

        let result: serde_json::Value = client
            .call("passkee.listCredentials", serde_json::json!({"rpId": "example.com"}))
            .await
            .unwrap();

        assert_eq!(result["echo"], true);

        let _ = std::fs::remove_file(sock_path);
    }
}
