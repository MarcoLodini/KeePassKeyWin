using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PassKee.Core.Ipc
{
    // JSON-RPC 2.0 request envelope.
    public sealed class JsonRpcRequest
    {
        [JsonProperty("jsonrpc")] public string Jsonrpc { get; set; } = "2.0";
        [JsonProperty("id")] public JToken? Id { get; set; }
        [JsonProperty("method")] public string Method { get; set; } = string.Empty;
        [JsonProperty("params")] public JToken? Params { get; set; }
    }

    // JSON-RPC 2.0 response envelope.
    public sealed class JsonRpcResponse
    {
        [JsonProperty("jsonrpc")] public string Jsonrpc { get; } = "2.0";
        [JsonProperty("id")] public JToken? Id { get; set; }
        [JsonProperty("result", NullValueHandling = NullValueHandling.Ignore)]
        public JToken? Result { get; set; }
        [JsonProperty("error", NullValueHandling = NullValueHandling.Ignore)]
        public JsonRpcError? Error { get; set; }
    }

    public sealed class JsonRpcError
    {
        [JsonProperty("code")] public int Code { get; set; }
        [JsonProperty("message")] public string Message { get; set; } = string.Empty;
        [JsonProperty("data", NullValueHandling = NullValueHandling.Ignore)]
        public JToken? Data { get; set; }
    }

    // Standard JSON-RPC error codes.
    public static class RpcErrorCode
    {
        public const int ParseError     = -32700;
        public const int InvalidRequest = -32600;
        public const int MethodNotFound = -32601;
        public const int InvalidParams  = -32602;
        public const int InternalError  = -32603;

        // Application-defined range: -32000 to -32099.
        public const int HandshakeRequired = -32000;
        public const int HandshakeInvalid  = -32001;
        public const int VaultLocked       = -32010;
        public const int CredentialNotFound = -32020;
    }

    // Per-connection mutable state threaded through each RPC dispatch.
    // plugin-core's Task #6 handlers key off HandshakeComplete to reject un-greeted requests.
    public sealed class ConnectionContext
    {
        public bool HandshakeComplete { get; set; }
        public string ClientPkgFamily { get; set; } = string.Empty;
    }
}
