using System;
using Newtonsoft.Json.Linq;

namespace KeePassKeyWin.Core.Ipc
{
    /// <summary>
    /// Handles the keepasskeywin.hello handshake method.
    ///
    /// Validates the client's package family name and a single-use HKCU nonce,
    /// then marks the connection as authenticated. Any subsequent calls to other
    /// methods will be rejected if HandshakeComplete is false.
    ///
    /// The nonce is stored at:
    ///   HKEY_CURRENT_USER\Software\KeePassKeyWin\HandshakeNonce
    /// Written by the plugin at startup, read by the sidecar, consumed (deleted) here.
    /// </summary>
    public static class HandshakeHandler
    {
        // Expected package family name for the KeePassKeyWin.Provider MSIX.
        // Verified at runtime; hardcoded here because v1 only ships one provider package.
        public const string ExpectedPkgFamily = "KeePassKeyWin.Provider_4fv17arhjxxvg";

        public static JToken Handle(JToken? @params, ConnectionContext context, INonceStore nonceStore)
        {
            if (context.HandshakeComplete)
                throw new RpcException(RpcErrorCode.HandshakeInvalid, "Handshake already completed.");

            var obj = @params as JObject
                ?? throw new RpcException(RpcErrorCode.InvalidParams, "params must be an object.");

            var clientPkg = obj["clientPkgFamilyName"]?.Value<string>();
            var nonce = obj["handshakeNonce"]?.Value<string>();

            if (string.IsNullOrEmpty(clientPkg) || string.IsNullOrEmpty(nonce))
                throw new RpcException(RpcErrorCode.InvalidParams, "clientPkgFamilyName and handshakeNonce are required.");

            if (!string.Equals(clientPkg, ExpectedPkgFamily, StringComparison.Ordinal))
                throw new RpcException(RpcErrorCode.HandshakeInvalid, "Unrecognised client package family.");

            if (!nonceStore.ConsumeNonce(nonce!))
                throw new RpcException(RpcErrorCode.HandshakeInvalid, "Invalid or already-used nonce.");

            context.HandshakeComplete = true;
            context.ClientPkgFamily = clientPkg!;

            return JValue.CreateString("ok");
        }
    }

    // Abstraction over HKCU nonce storage — real impl writes to the registry on Windows;
    // test impl uses an in-memory dictionary.
    public interface INonceStore
    {
        // Returns true and deletes the nonce if it matches; false otherwise.
        bool ConsumeNonce(string nonce);
    }
}
