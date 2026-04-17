using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using PassKee.Core.Cbor;
using PassKee.Core.Crypto;
using PassKee.Core.Storage;
using PassKee.Core.WebAuthn;

namespace PassKee.Core.Ipc
{
    /// <summary>
    /// Handles the five vault RPC methods dispatched from RpcDispatcher.VaultHandler:
    ///   passkee.createPasskey, passkee.listCredentials, passkee.signAssertion,
    ///   passkee.deleteCredential, passkee.enumerateForSync.
    ///
    /// All methods require a completed handshake (enforced upstream in RpcDispatcher).
    /// All methods throw RpcException on invalid params or vault-locked state.
    /// </summary>
    public sealed class VaultHandler
    {
        private readonly IPasskeyStore _store;

        public VaultHandler(IPasskeyStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
        }

        /// <summary>
        /// Entry point wired into RpcDispatcher.VaultHandler.
        /// Returns a result JToken or throws RpcException.
        /// </summary>
        public JToken? Handle(string method, JToken? @params)
        {
            RequireVaultOpen();

            return method switch
            {
                "passkee.createPasskey"     => CreatePasskey(@params),
                "passkee.listCredentials"   => ListCredentials(@params),
                "passkee.signAssertion"     => SignAssertion(@params),
                "passkee.deleteCredential"  => DeleteCredential(@params),
                "passkee.enumerateForSync"  => EnumerateForSync(),
                _ => throw new RpcException(RpcErrorCode.MethodNotFound, $"Method not found: {method}")
            };
        }

        // passkee.createPasskey
        // params: { rpId, rpName, userHandle, userName, userDisplayName }
        // result: { credentialId, authData (base64), publicKeyCose (base64) }
        private JToken CreatePasskey(JToken? @params)
        {
            var obj = RequireObject(@params, "passkee.createPasskey");

            var rpId            = RequireString(obj, "rpId");
            var rpName          = OptionalString(obj, "rpName") ?? rpId;
            var userHandle      = RequireString(obj, "userHandle");     // Base64URL
            var userName        = RequireString(obj, "userName");
            var userDisplayName = OptionalString(obj, "userDisplayName") ?? userName;

            var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();
            var coseKey = CoseKey.Encode(x, y);

            // 32 random bytes as credential ID.
            var rawCredId = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(rawCredId);

            var credentialId = Base64Url.Encode(rawCredId);

            var authData = AuthDataBuilder.Build(
                rpId,
                rawCredId,
                x, y,
                userVerified: true);

            var record = new PasskeyRecord
            {
                CredentialId      = credentialId,
                RpId              = rpId,
                RpName            = rpName,
                UserHandle        = userHandle,
                UserName          = userName,
                UserDisplayName   = userDisplayName,
                AlgId             = -7,
                PrivateKeyPkcs8   = Convert.ToBase64String(pkcs8),
                PublicKeyCose     = coseKey,
            };
            _store.Add(record);

            return new JObject
            {
                ["credentialId"]  = credentialId,
                ["authData"]      = Convert.ToBase64String(authData),
                ["publicKeyCose"] = Convert.ToBase64String(coseKey),
            };
        }

        // passkee.listCredentials
        // params: { rpId }
        // result: [ { credentialId, userHandle, userName, userDisplayName }, ... ]
        private JToken ListCredentials(JToken? @params)
        {
            var obj  = RequireObject(@params, "passkee.listCredentials");
            var rpId = RequireString(obj, "rpId");

            var records = _store.FindByRpId(rpId);
            var arr = new JArray();
            foreach (var r in records)
            {
                arr.Add(new JObject
                {
                    ["credentialId"]      = r.CredentialId,
                    ["userHandle"]        = r.UserHandle,
                    ["userName"]          = r.UserName,
                    ["userDisplayName"]   = r.UserDisplayName,
                });
            }
            return arr;
        }

        // passkee.signAssertion
        // params: { credentialId, authData (base64), clientDataHash (base64) }
        // result: { signature (base64), authData (base64), userHandle }
        private JToken SignAssertion(JToken? @params)
        {
            var obj             = RequireObject(@params, "passkee.signAssertion");
            var credentialId    = RequireString(obj, "credentialId");
            var authDataB64     = RequireString(obj, "authData");
            var clientDataHashB64 = RequireString(obj, "clientDataHash");

            var record = _store.FindById(credentialId)
                ?? throw new RpcException(RpcErrorCode.CredentialNotFound,
                    $"Credential not found: {credentialId}");

            byte[] authDataBytes;
            byte[] clientDataHash;
            try
            {
                authDataBytes  = Convert.FromBase64String(authDataB64);
                clientDataHash = Convert.FromBase64String(clientDataHashB64);
            }
            catch (FormatException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "authData or clientDataHash is not valid base64: " + ex.Message);
            }

            // WebAuthn §7.2: signature covers authData || clientDataHash.
            var signInput = new byte[authDataBytes.Length + clientDataHash.Length];
            Buffer.BlockCopy(authDataBytes, 0, signInput, 0, authDataBytes.Length);
            Buffer.BlockCopy(clientDataHash, 0, signInput, authDataBytes.Length, clientDataHash.Length);

            var pkcs8 = Convert.FromBase64String(record.PrivateKeyPkcs8);
            var signature = EcdsaSigner.Sign(pkcs8, signInput);

            // Build assertion authData (no AT bit, signCount=0).
            var assertionAuthData = AuthDataBuilder.BuildAssertion(record.RpId, userVerified: true);

            return new JObject
            {
                ["signature"]   = Convert.ToBase64String(signature),
                ["authData"]    = Convert.ToBase64String(assertionAuthData),
                ["userHandle"]  = record.UserHandle,
            };
        }

        // passkee.deleteCredential
        // params: { credentialId }
        // result: { deleted: true|false }
        private JToken DeleteCredential(JToken? @params)
        {
            var obj          = RequireObject(@params, "passkee.deleteCredential");
            var credentialId = RequireString(obj, "credentialId");

            bool deleted = _store.Delete(credentialId);
            return new JObject { ["deleted"] = deleted };
        }

        // passkee.enumerateForSync
        // params: none
        // result: [ { credentialId, rpId, rpName, userHandle, userName, userDisplayName, algId }, ... ]
        private JToken EnumerateForSync()
        {
            var records = _store.GetAll();
            var arr = new JArray();
            foreach (var r in records)
            {
                arr.Add(new JObject
                {
                    ["credentialId"]      = r.CredentialId,
                    ["rpId"]              = r.RpId,
                    ["rpName"]            = r.RpName,
                    ["userHandle"]        = r.UserHandle,
                    ["userName"]          = r.UserName,
                    ["userDisplayName"]   = r.UserDisplayName,
                    ["algId"]             = r.AlgId,
                });
            }
            return arr;
        }

        private void RequireVaultOpen()
        {
            if (!_store.IsVaultOpen)
                throw new RpcException(RpcErrorCode.VaultLocked, "KeePass vault is not open.");
        }

        private static JObject RequireObject(JToken? token, string method)
            => token as JObject
               ?? throw new RpcException(RpcErrorCode.InvalidParams,
                   $"{method}: params must be a JSON object.");

        private static string RequireString(JObject obj, string key)
        {
            var val = obj[key]?.Value<string>();
            if (string.IsNullOrEmpty(val))
                throw new RpcException(RpcErrorCode.InvalidParams,
                    $"Missing or empty required parameter: {key}");
            return val!;
        }

        private static string? OptionalString(JObject obj, string key)
            => obj[key]?.Value<string>();
    }
}
