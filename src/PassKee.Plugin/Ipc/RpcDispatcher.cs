using System;
using Newtonsoft.Json.Linq;
using PassKee.Core.Ipc;

namespace PassKee.Plugin.Ipc
{
    /// <summary>
    /// Routes JSON-RPC method calls to their handlers.
    ///
    /// hello — handled here (handshake before any authentication check).
    /// All other methods require HandshakeComplete; until plugin-core Task #6 wires
    /// them up they return method_not_found.
    /// </summary>
    public sealed class RpcDispatcher
    {
        private readonly INonceStore _nonceStore;

        // plugin-core Task #6 injects the vault handler via this delegate.
        // Null until wired; returns method_not_found for all unknown methods.
        public Func<string, JToken?, JToken?>? VaultHandler { get; set; }

        public RpcDispatcher(INonceStore nonceStore)
        {
            _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        }

        public JToken? Dispatch(JsonRpcRequest request, ConnectionContext context)
        {
            if (request.Method == "passkee.hello")
                return HandshakeHandler.Handle(request.Params, context, _nonceStore);

            if (!context.HandshakeComplete)
                throw new RpcException(RpcErrorCode.HandshakeRequired, "Handshake not completed.");

            if (VaultHandler != null)
                return VaultHandler(request.Method, request.Params);

            throw new RpcException(RpcErrorCode.MethodNotFound, $"Method not found: {request.Method}");
        }
    }
}
