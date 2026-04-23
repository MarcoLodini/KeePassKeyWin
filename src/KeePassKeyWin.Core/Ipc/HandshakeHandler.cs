using System;
using System.Diagnostics;
using KeePassKeyWin.Core.Crypto;
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
    /// Since Phase 5.UV.1, the hello params may optionally include
    /// <c>opSignPublicKeyB64</c> (base64-std-encoded <c>BCRYPT_PUBLIC_KEY_BLOB</c> bytes).
    /// If present, the bytes are decoded and cached in <see cref="OpSignPubKeyCache"/>.
    /// Absence is tolerated for backward compatibility with sidecars that predate 5.UV.1;
    /// Phase 5.UV.4 will tighten this once UV verification depends on the cached key.
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

            // 5.UV.1: cache the op-signing pubkey if the sidecar sent it.
            // Absence is tolerated (backward-compat with pre-5.UV.1 sidecars).
            // 5.UV.4 will tighten this once UV verification depends on the cached key.
            var opSignKeyB64 = obj["opSignPublicKeyB64"]?.Value<string>();
            if (!string.IsNullOrEmpty(opSignKeyB64))
            {
                try
                {
                    var keyBytes = Convert.FromBase64String(opSignKeyB64!);
                    OpSignPubKeyCache.Set(keyBytes);
                    Debug.WriteLine($"[handshake] op-sign pubkey cached ({keyBytes.Length}B)");
                }
                catch (FormatException ex)
                {
                    // Malformed base64: log and continue. The handshake itself is still valid;
                    // UV verification will simply fail later when the cache is empty.
                    Debug.WriteLine($"[handshake] opSignPublicKeyB64 is not valid base64 — ignored: {ex.Message}");
                }
            }
            else
            {
                Debug.WriteLine("[handshake] opSignPublicKeyB64 absent — op-sign pubkey not cached (pre-5.UV.1 sidecar or key-fetch failed)");
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
