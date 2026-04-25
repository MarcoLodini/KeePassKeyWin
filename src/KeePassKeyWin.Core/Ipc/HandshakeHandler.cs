using System;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.Diagnostics;
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
    ///
    /// Since Phase 5.UV.4, the hello params <b>must</b> include
    /// <c>opSignPublicKeyB64</c> (base64-std-encoded <c>BCRYPT_PUBLIC_KEY_BLOB</c> bytes).
    /// Absence or malformed base64 throws <see cref="RpcException"/> with
    /// <see cref="RpcErrorCode.InvalidParams"/>. The bytes are decoded and cached
    /// in <see cref="OpSignPubKeyCache"/> for UV signature verification.
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

            // 5.UV.4: opSignPublicKeyB64 is now required — absence or malformed
            // base64 means the sidecar cannot provide UV signature verification,
            // so the handshake itself is rejected (fail-closed, not deferred).
            var opSignKeyB64 = obj["opSignPublicKeyB64"]?.Value<string>();
            if (string.IsNullOrEmpty(opSignKeyB64))
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "opSignPublicKeyB64 is required in keepasskeywin.hello params.");

            try
            {
                var keyBytes = Convert.FromBase64String(opSignKeyB64!);
                OpSignPubKeyCache.Set(keyBytes);
                TraceLogger.WriteLine($"[handshake] op-sign pubkey cached ({keyBytes.Length}B)");
            }
            catch (FormatException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    $"opSignPublicKeyB64 is not valid base64: {ex.Message}");
            }

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
