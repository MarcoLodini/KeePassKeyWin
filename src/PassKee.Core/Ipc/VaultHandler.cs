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
                "passkee.createPasskey"        => CreatePasskey(@params),
                "passkee.listCredentials"      => ListCredentials(@params),
                "passkee.signAssertion"        => SignAssertion(@params),
                "passkee.deleteCredential"     => DeleteCredential(@params),
                "passkee.enumerateForSync"     => EnumerateForSync(),
                "passkee.makeCredentialRaw"    => HandleMakeCredentialRaw(@params),
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

        // passkee.makeCredentialRaw
        // params: { cbor: "<base64-std of CTAP2 authenticatorMakeCredential bytes>", uv: true|false }
        // result: { cbor: "<base64-std of CTAP2 attestation object bytes>" }
        //
        // The Rust sidecar performs Windows Hello UV before calling this method.
        // The 'uv' flag is trusted as-is and reflected in the authData flags byte.
        private JToken HandleMakeCredentialRaw(JToken? @params)
        {
            var obj = RequireObject(@params, "passkee.makeCredentialRaw");

            // Extract 'cbor' (base64-std) and 'uv' (bool) from params.
            var cborB64 = RequireString(obj, "cbor");
            var uvToken = obj["uv"];
            bool uv = uvToken?.Value<bool>() ?? false;

            // Decode the outer CBOR bytes (base64-std, not base64url).
            byte[] cborBytes;
            try
            {
                cborBytes = Convert.FromBase64String(cborB64);
            }
            catch (FormatException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "passkee.makeCredentialRaw: 'cbor' is not valid base64: " + ex.Message);
            }

            // Parse the CTAP2 authenticatorMakeCredential input map.
            MakeCredentialRequest req;
            try
            {
                req = ParseMakeCredentialCbor(cborBytes);
            }
            catch (CborReaderException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "passkee.makeCredentialRaw: malformed CBOR: " + ex.Message);
            }

            // Check for excluded credentials.
            foreach (var excludedId in req.ExcludeList)
            {
                if (_store.FindById(excludedId) != null)
                    throw new RpcException(RpcErrorCode.CredentialExcluded,
                        $"A credential matching the exclude list is already registered: {excludedId}");
            }

            // Generate EC P-256 key pair and credential ID.
            var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();
            var coseKey = CoseKey.Encode(x, y);

            var rawCredId = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(rawCredId);
            var credentialId = Base64Url.Encode(rawCredId);

            // Build authenticatorData with the UV flag from the sidecar.
            var authData = AuthDataBuilder.Build(
                req.RpId,
                rawCredId,
                x, y,
                userVerified: uv);

            // Persist the new credential.
            var record = new PasskeyRecord
            {
                CredentialId    = credentialId,
                RpId            = req.RpId,
                RpName          = req.RpName,
                UserHandle      = req.UserHandle,
                UserName        = req.UserName,
                UserDisplayName = req.UserDisplayName,
                AlgId           = -7,
                PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
                PublicKeyCose   = coseKey,
            };
            _store.Add(record);

            // Encode CTAP2 attestation object: {1: "none", 2: authData, 3: {}}.
            var responseBytes = BuildAttestationObject(authData);

            return new JObject
            {
                ["cbor"] = Convert.ToBase64String(responseBytes),
            };
        }

        /// <summary>
        /// Parses the CTAP2 authenticatorMakeCredential input map (§6.1.1).
        /// Validates required fields and throws RpcException or CborReaderException on error.
        /// </summary>
        private MakeCredentialRequest ParseMakeCredentialCbor(byte[] data)
        {
            var reader = new CborReader(data);
            int mapCount = reader.ReadMapHeader();

            byte[]? clientDataHash = null;
            string? rpId           = null;
            string? rpName         = null;
            string? userHandle     = null; // base64url
            string? userName       = null;
            string? userDisplayName = null;
            bool hasEs256          = false;
            var excludeList        = new List<string>();

            for (int i = 0; i < mapCount; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                switch (key)
                {
                    case 1: // clientDataHash — byte string, must be 32 bytes
                        clientDataHash = reader.ReadByteString();
                        if (clientDataHash.Length != 32)
                            throw new RpcException(RpcErrorCode.InvalidParams,
                                $"passkee.makeCredentialRaw: clientDataHash must be 32 bytes, got {clientDataHash.Length}.");
                        break;

                    case 2: // rp map — {id (required), name (optional)}
                    {
                        int rpCount = reader.ReadMapHeader();
                        for (int k = 0; k < rpCount; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "id")
                                rpId = reader.ReadTextString();
                            else if (field == "name")
                                rpName = reader.ReadTextString();
                            else
                                reader.SkipValue();
                        }
                        break;
                    }

                    case 3: // user map — {id (byte string → base64url), name (required), displayName (optional)}
                    {
                        int userCount = reader.ReadMapHeader();
                        for (int k = 0; k < userCount; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "id")
                                userHandle = Base64Url.Encode(reader.ReadByteString());
                            else if (field == "name")
                                userName = reader.ReadTextString();
                            else if (field == "displayName")
                                userDisplayName = reader.ReadTextString();
                            else
                                reader.SkipValue();
                        }
                        break;
                    }

                    case 4: // pubKeyCredParams — array of {type, alg}; must contain ES256 (-7)
                    {
                        int arrCount = reader.ReadArrayHeader();
                        for (int k = 0; k < arrCount; k++)
                        {
                            int paramCount = reader.ReadMapHeader();
                            string? paramType = null;
                            long? algId       = null;
                            for (int p = 0; p < paramCount; p++)
                            {
                                string field = reader.ReadTextString();
                                if (field == "alg")
                                    algId = reader.ReadNegativeInt();
                                else if (field == "type")
                                    paramType = reader.ReadTextString();
                                else
                                    reader.SkipValue();
                            }
                            if (algId == -7 && paramType == "public-key")
                                hasEs256 = true;
                        }
                        break;
                    }

                    case 5: // excludeList — array of credential descriptors {id (byte string), ...}
                    {
                        int exCount = reader.ReadArrayHeader();
                        for (int k = 0; k < exCount; k++)
                        {
                            int descCount = reader.ReadMapHeader();
                            byte[]? descId = null;
                            for (int p = 0; p < descCount; p++)
                            {
                                string field = reader.ReadTextString();
                                if (field == "id")
                                    descId = reader.ReadByteString();
                                else
                                    reader.SkipValue();
                            }
                            if (descId != null)
                                excludeList.Add(Base64Url.Encode(descId));
                        }
                        break;
                    }

                    default: // keys 6 (extensions), 7 (options), 8 (pinUvAuthParam), 9 (pinUvAuthProtocol)
                        reader.SkipValue();
                        break;
                }
            }

            // Validate required fields.
            if (clientDataHash == null)
                throw new RpcException(RpcErrorCode.InvalidParams, "passkee.makeCredentialRaw: missing required CTAP2 key 1 (clientDataHash).");
            if (string.IsNullOrEmpty(rpId))
                throw new RpcException(RpcErrorCode.InvalidParams, "passkee.makeCredentialRaw: missing required RP id in key 2 (rp map).");
            if (string.IsNullOrEmpty(userHandle))
                throw new RpcException(RpcErrorCode.InvalidParams, "passkee.makeCredentialRaw: missing required user.id in key 3 (user map).");
            if (string.IsNullOrEmpty(userName))
                throw new RpcException(RpcErrorCode.InvalidParams, "passkee.makeCredentialRaw: missing required user.name in key 3 (user map).");
            if (!hasEs256)
                throw new RpcException(RpcErrorCode.UnsupportedAlgorithm,
                    "passkee.makeCredentialRaw: no supported algorithm found in pubKeyCredParams (ES256/-7 required).");

            return new MakeCredentialRequest
            {
                ClientDataHash  = clientDataHash,
                RpId            = rpId!,
                RpName          = string.IsNullOrEmpty(rpName) ? rpId! : rpName!,
                UserHandle      = userHandle!,
                UserName        = userName!,
                UserDisplayName = string.IsNullOrEmpty(userDisplayName) ? userName! : userDisplayName!,
                ExcludeList     = excludeList,
            };
        }

        /// <summary>
        /// Encodes a CTAP2 "none" attestation object per CTAP 2.1 §6.1 (authenticatorMakeCredential response).
        /// Integer keys (NOT the WebAuthn L3 §6.5.5 text-keyed shape — that's what webauthn.dll produces
        /// AFTER converting CTAP2 to the browser-facing attestationObject).
        ///
        /// Shape: { 1: "none" (fmt), 2: authData (byte string), 3: {} (attStmt) }.
        /// CborWriter sorts by bytewise-lex — for small uints 1,2,3 that's the natural numeric order.
        /// </summary>
        private static byte[] BuildAttestationObject(byte[] authData)
        {
            var w = new CborWriter();

            byte[] EncodeUint(ulong v)   { var ww = new CborWriter(); ww.WriteUnsignedInt(v); return ww.Encode(); }
            byte[] EncodeTstr(string s)  { var ww = new CborWriter(); ww.WriteTextString(s); return ww.Encode(); }
            byte[] EncodeBstr(byte[] b)  { var ww = new CborWriter(); ww.WriteByteString(b); return ww.Encode(); }
            byte[] EncodeEmptyMap()      { var ww = new CborWriter(); ww.WriteMap(Array.Empty<(byte[], byte[])>()); return ww.Encode(); }

            w.WriteMap(new[]
            {
                (EncodeUint(1), EncodeTstr("none")),   // fmt
                (EncodeUint(2), EncodeBstr(authData)), // authData
                (EncodeUint(3), EncodeEmptyMap()),     // attStmt
            });
            return w.Encode();
        }

        // Internal data-transfer object for parsed CTAP2 MakeCredential input.
        private sealed class MakeCredentialRequest
        {
            public byte[]      ClientDataHash  { get; set; } = Array.Empty<byte>();
            public string      RpId            { get; set; } = string.Empty;
            public string      RpName          { get; set; } = string.Empty;
            public string      UserHandle      { get; set; } = string.Empty;  // base64url
            public string      UserName        { get; set; } = string.Empty;
            public string      UserDisplayName { get; set; } = string.Empty;
            public List<string> ExcludeList    { get; set; } = new List<string>();
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
