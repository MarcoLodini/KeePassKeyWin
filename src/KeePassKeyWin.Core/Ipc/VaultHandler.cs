using System;
using System.Collections.Generic;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.Storage;
using KeePassKeyWin.Core.WebAuthn;

// Supported COSE algorithm identifiers.
// ES256 = -7  (ECDSA P-256 / SHA-256)
// RS256 = -257 (RSASSA-PKCS1-v1_5 / SHA-256, RFC 8230)

namespace KeePassKeyWin.Core.Ipc
{
    /// <summary>
    /// Handles the five vault RPC methods dispatched from RpcDispatcher.VaultHandler:
    ///   keepasskeywin.createPasskey, keepasskeywin.listCredentials, keepasskeywin.signAssertion,
    ///   keepasskeywin.deleteCredential, keepasskeywin.enumerateForSync.
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
                "keepasskeywin.createPasskey"        => CreatePasskey(@params),
                "keepasskeywin.listCredentials"      => ListCredentials(@params),
                "keepasskeywin.signAssertion"        => SignAssertion(@params),
                "keepasskeywin.deleteCredential"     => DeleteCredential(@params),
                "keepasskeywin.enumerateForSync"     => EnumerateForSync(),
                "keepasskeywin.makeCredentialRaw"    => HandleMakeCredentialRaw(@params),
                "keepasskeywin.getAssertionRaw"      => HandleGetAssertionRaw(@params),
                _ => throw new RpcException(RpcErrorCode.MethodNotFound, $"Method not found: {method}")
            };
        }

        // keepasskeywin.createPasskey
        // params: { rpId, rpName, userHandle, userName, userDisplayName }
        // result: { credentialId, authData (base64), publicKeyCose (base64) }
        private JToken CreatePasskey(JToken? @params)
        {
            var obj = RequireObject(@params, "keepasskeywin.createPasskey");

            var rpId            = RequireString(obj, "rpId");
            var rpName          = OptionalString(obj, "rpName") ?? rpId;
            var userHandle      = RequireString(obj, "userHandle");     // Base64URL
            var userName        = RequireString(obj, "userName");
            var userDisplayName = OptionalString(obj, "userDisplayName") ?? userName;

            // CreatePasskey has no pubKeyCredParams input — default to ES256.
            var (pkcs8, coseKey) = GenerateKeyPairAndCoseKey(-7);

            // 32 random bytes as credential ID.
            var rawCredId = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(rawCredId);

            var credentialId = Base64Url.Encode(rawCredId);

            var authData = AuthDataBuilder.Build(
                rpId,
                rawCredId,
                coseKey,
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

        // keepasskeywin.makeCredentialRaw
        // params: { cbor: "<base64-std of CTAP2 authenticatorMakeCredential bytes>", uv: true|false }
        // result: { cbor: "<base64-std of CTAP2 attestation object bytes>" }
        //
        // The Rust sidecar performs Windows Hello UV before calling this method.
        // The 'uv' flag is trusted as-is and reflected in the authData flags byte.
        private JToken HandleMakeCredentialRaw(JToken? @params)
        {
            var obj = RequireObject(@params, "keepasskeywin.makeCredentialRaw");

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
                    "keepasskeywin.makeCredentialRaw: 'cbor' is not valid base64: " + ex.Message);
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
                    "keepasskeywin.makeCredentialRaw: malformed CBOR: " + ex.Message);
            }

            // Check for excluded credentials.
            foreach (var excludedId in req.ExcludeList)
            {
                if (_store.FindById(excludedId) != null)
                    throw new RpcException(RpcErrorCode.CredentialExcluded,
                        $"A credential matching the exclude list is already registered: {excludedId}");
            }

            // Select algorithm: prefer ES256 when both offered; fall back to RS256 if ES256 absent.
            // Tiebreaker policy: ES256 produces smaller keys (~77 B vs ~270 B for RS256-2048)
            // and faster sign operations — prefer it whenever the RP accepts it.
            int selectedAlg = SelectAlgorithm(req.RequestedAlgs);

            // Generate key pair and COSE_Key for the selected algorithm.
            var (pkcs8, coseKey) = GenerateKeyPairAndCoseKey(selectedAlg);

            var rawCredId = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(rawCredId);
            var credentialId = Base64Url.Encode(rawCredId);

            // Build authenticatorData with the UV flag from the sidecar.
            var authData = AuthDataBuilder.Build(
                req.RpId,
                rawCredId,
                coseKey,
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
                AlgId           = selectedAlg,
                PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
                PublicKeyCose   = coseKey,
            };
            _store.Add(record);

            // Encode CTAP2 attestation object: {1: "none", 2: authData, 3: {}}.
            var responseBytes = BuildAttestationObject(authData);

            // Include the user/RP metadata the Rust sidecar needs to populate
            // WEBAUTHN_PLUGIN_ADD_CREDENTIAL so Windows' OS-wide credential store
            // knows this credential exists (Phase 4 login picker). credentialIdB64Url
            // and userHandleB64Url are base64url-no-pad, ready to pass through.
            return new JObject
            {
                ["cbor"]               = Convert.ToBase64String(responseBytes),
                ["credentialIdB64Url"] = record.CredentialId,
                ["rpId"]               = req.RpId,
                ["rpName"]             = req.RpName,
                ["userHandleB64Url"]   = req.UserHandle,
                ["userName"]           = req.UserName,
                ["userDisplayName"]    = req.UserDisplayName,
            };
        }

        // keepasskeywin.getAssertionRaw
        // params: { cbor: "<base64-std of CTAP2 authenticatorGetAssertion request bytes>", uv: true|false }
        // result: { cbor: "<base64-std of CTAP2 authenticatorGetAssertion response bytes>" }
        //
        // The Rust sidecar performs Windows Hello UV before calling this method; the
        // 'uv' flag is trusted as-is and reflected in the assertion authData flags byte.
        // Error codes specific to this method:
        //   CredentialNotFound (-32020) — allowList present but no match, or discoverable
        //     flow and no credential exists for the given rpId.
        //   InvalidOption (-32041) — caller requested options.up=false (unsupported).
        //
        // Discoverable credential flow (CTAP 2.1 §6.2):
        //   An absent or empty allowList (key 3) signals a discoverable credential
        //   request. We query the store by rpId and select the first match.
        //   Per §6.2, the user entity (CTAP2 response key 4) is mandatory so the RP
        //   can identify which credential was used. We include user.id unconditionally
        //   and user.name / user.displayName only when uv=true (CTAP 2.1 §6.2 PII rule:
        //   user-identifiable info MUST NOT be returned without user verification).
        //   Note: v1 returns only the first matching credential; multi-credential
        //   selection (numberOfCredentials / authenticatorGetNextAssertion) is deferred.
        private JToken HandleGetAssertionRaw(JToken? @params)
        {
            var obj = RequireObject(@params, "keepasskeywin.getAssertionRaw");

            var cborB64 = RequireString(obj, "cbor");
            var uvToken = obj["uv"];
            bool uv = uvToken?.Value<bool>() ?? false;

            byte[] cborBytes;
            try
            {
                cborBytes = Convert.FromBase64String(cborB64);
            }
            catch (FormatException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "keepasskeywin.getAssertionRaw: 'cbor' is not valid base64: " + ex.Message);
            }

            GetAssertionRequest req;
            try
            {
                req = ParseGetAssertionCbor(cborBytes);
            }
            catch (CborReaderException ex)
            {
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "keepasskeywin.getAssertionRaw: malformed CBOR: " + ex.Message);
            }

            Debug.WriteLine($"[getAssert] ENTRY clientDataHash_len={req.ClientDataHash.Length} rpId={req.RpId} allowList_count={req.AllowListCredIds.Count}");

            // options.up=false is forbidden by our v1 (we always require user presence).
            if (!req.OptionsUp)
            {
                Debug.WriteLine("[getAssert] REJECT options.up=false");
                throw new RpcException(RpcErrorCode.InvalidOption,
                    "keepasskeywin.getAssertionRaw: options.up=false is not supported.");
            }

            bool isDiscoverable = req.AllowListCredIds.Count == 0;
            PasskeyRecord? selected = null;

            if (isDiscoverable)
            {
                // Discoverable credential flow: find all credentials for the rpId and
                // select the first. v1 limitation: multiple matches return only the
                // first; numberOfCredentials / authenticatorGetNextAssertion deferred.
                var candidates = _store.FindByRpId(req.RpId);
                if (candidates.Count == 0)
                {
                    Debug.WriteLine($"[getAssert] REJECT discoverable — no credential found for rpId={req.RpId}");
                    throw new RpcException(RpcErrorCode.CredentialNotFound,
                        "keepasskeywin.getAssertionRaw: no passkey found for RP '" + req.RpId + "'.");
                }
                selected = candidates[0];
                Debug.WriteLine($"[getAssert] discoverable — selected credentialId={SafePrefix(selected.CredentialId, 8)}");
            }
            else
            {
                // Non-discoverable: select the first allowList entry that exists in the vault.
                foreach (var rawId in req.AllowListCredIds)
                {
                    var credId = Base64Url.Encode(rawId);
                    var hit = _store.FindById(credId);
                    if (hit != null)
                    {
                        selected = hit;
                        break;
                    }
                }
                if (selected == null)
                {
                    Debug.WriteLine("[getAssert] REJECT no allowList credential matched the vault");
                    throw new RpcException(RpcErrorCode.CredentialNotFound,
                        "keepasskeywin.getAssertionRaw: no credential in allowList matches the vault.");
                }
            }

            var oldCount = selected.SignCount;
            uint newCount = _store.IncrementSignCount(selected.CredentialId);
            Debug.WriteLine($"[getAssert] selected credentialId={SafePrefix(selected.CredentialId, 8)} userName={selected.UserName}");
            Debug.WriteLine($"[getAssert] signCount {oldCount} -> {newCount}");

            // Build 37-byte assertion authData (no attested credential data).
            var authData = AuthDataBuilder.BuildAssertion(selected.RpId, userVerified: uv, signCount: newCount);

            // WebAuthn §7.2: signature covers authData || clientDataHash.
            var signInput = new byte[authData.Length + req.ClientDataHash.Length];
            Buffer.BlockCopy(authData, 0, signInput, 0, authData.Length);
            Buffer.BlockCopy(req.ClientDataHash, 0, signInput, authData.Length, req.ClientDataHash.Length);

            var pkcs8 = Convert.FromBase64String(selected.PrivateKeyPkcs8);
            var signature = SignWithAlgorithm(pkcs8, signInput, selected.AlgId);

            // Convert the selected credential's stored base64url-no-pad ID back to raw
            // bytes to echo in the response descriptor (CTAP2 allows only raw bstr).
            var rawCredIdBytes = Base64Url.Decode(selected.CredentialId);

            // For discoverable credentials, include the user entity (CTAP2 key 4) so
            // the RP can identify which account was used. Non-discoverable: userRecord=null.
            PasskeyRecord? userRecord = isDiscoverable ? selected : null;
            var responseBytes = BuildAssertionResponse(rawCredIdBytes, authData, signature, userRecord, uv);
            Debug.WriteLine($"[getAssert] DONE response_size={responseBytes.Length}B discoverable={isDiscoverable}");

            return new JObject
            {
                ["cbor"] = Convert.ToBase64String(responseBytes),
            };
        }

        private static string SafePrefix(string s, int n)
            => s.Length <= n ? s : s.Substring(0, n);

        /// <summary>
        /// Parses the CTAP2 authenticatorGetAssertion input map (§6.2).
        ///
        /// Required keys:
        ///   1 = rpId (text string)
        ///   2 = clientDataHash (byte string, exactly 32 bytes)
        ///
        /// Optional keys:
        ///   3 = allowList (array of PublicKeyCredentialDescriptor maps)
        ///       Absent or empty → discoverable credential flow.
        ///   4 = extensions (map)           — skipped
        ///   5 = options (map)              — {up, uv} parsed; rk ignored
        ///   6 = pinUvAuthParam             — skipped
        ///   7 = pinUvAuthProtocol          — skipped
        ///
        /// PublicKeyCredentialDescriptor is a text-keyed map with "type", "id",
        /// optional "transports". Entries whose "type" is not "public-key" are
        /// silently filtered out (per CTAP 2.1 §6.2 unknown-type handling).
        /// </summary>
        private GetAssertionRequest ParseGetAssertionCbor(byte[] data)
        {
            var reader = new CborReader(data);
            int mapCount = reader.ReadMapHeader();

            string? rpId = null;
            byte[]? clientDataHash = null;
            var allowList = new List<byte[]>();
            bool optionsUp = true;  // CTAP 2.1 §6.2: up defaults to true
            bool optionsUv = false; // and uv defaults to false

            for (int i = 0; i < mapCount; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                switch (key)
                {
                    case 1: // rpId
                        rpId = reader.ReadTextString();
                        break;

                    case 2: // clientDataHash
                        clientDataHash = reader.ReadByteString();
                        if (clientDataHash.Length != 32)
                            throw new RpcException(RpcErrorCode.InvalidParams,
                                $"keepasskeywin.getAssertionRaw: clientDataHash must be 32 bytes, got {clientDataHash.Length}.");
                        break;

                    case 3: // allowList (optional: absent or empty → discoverable credential flow)
                    {
                        int arrCount = reader.ReadArrayHeader();
                        for (int k = 0; k < arrCount; k++)
                        {
                            int descCount = reader.ReadMapHeader();
                            byte[]? descId = null;
                            string? descType = null;
                            for (int p = 0; p < descCount; p++)
                            {
                                string field = reader.ReadTextString();
                                if (field == "id")
                                    descId = reader.ReadByteString();
                                else if (field == "type")
                                    descType = reader.ReadTextString();
                                else
                                    reader.SkipValue();
                            }
                            // Silently drop unknown types; CTAP2 §6.2 allows unknown
                            // "type" values to be ignored rather than rejected.
                            if (descId != null && descType == "public-key")
                                allowList.Add(descId);
                        }
                        break;
                    }

                    case 5: // options
                    {
                        int optCount = reader.ReadMapHeader();
                        for (int k = 0; k < optCount; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "up")
                                optionsUp = reader.ReadBool();
                            else if (field == "uv")
                                optionsUv = reader.ReadBool();
                            else
                                reader.SkipValue(); // rk, any future fields
                        }
                        break;
                    }

                    default:
                        // extensions (4), pinUvAuthParam (6), pinUvAuthProtocol (7), and anything else: skip.
                        reader.SkipValue();
                        break;
                }
            }

            if (string.IsNullOrEmpty(rpId))
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "keepasskeywin.getAssertionRaw: missing required CTAP2 key 1 (rpId).");
            if (clientDataHash == null)
                throw new RpcException(RpcErrorCode.InvalidParams,
                    "keepasskeywin.getAssertionRaw: missing required CTAP2 key 2 (clientDataHash).");
            // Key 3 (allowList) is optional: absent or empty → discoverable credential flow.

            return new GetAssertionRequest
            {
                RpId             = rpId!,
                ClientDataHash   = clientDataHash,
                AllowListCredIds = allowList,
                OptionsUp        = optionsUp,
                OptionsUv        = optionsUv,
            };
        }

        /// <summary>
        /// Encodes a CTAP2 authenticatorGetAssertion response per CTAP 2.1 §6.2.
        ///
        /// Top-level shape is INTEGER-keyed (NOT the WebAuthn L3 text-keyed shape
        /// — webauthn.dll converts CTAP2 ↔ WebAuthn itself):
        ///   1 = PublicKeyCredentialDescriptor (text-keyed: "id" (bstr), "type" (tstr))
        ///   2 = authData (byte string, 37 bytes)
        ///   3 = signature (byte string, DER-encoded ECDSA)
        ///   4 = user entity map (text-keyed) — present only for discoverable credentials
        ///       (when <paramref name="userRecord"/> is non-null). Contains:
        ///         "id"          → bstr (raw user handle bytes)
        ///         "name"        → tstr (only when uv=true, per CTAP 2.1 §6.2 PII rule)
        ///         "displayName" → tstr (only when uv=true)
        ///
        /// Nested descriptor keys sort bytewise-lex: "id" (0x62 0x69 0x64) comes
        /// before "type" (0x64 0x74 0x79 0x70 0x65). User entity inner keys also
        /// sort bytewise-lex: "id" (0x62) before "name" (0x64) before "displayName" (0x6B).
        ///
        /// Factored out so the Phase 4 hex-shape test can encode with fixed inputs —
        /// ECDSA signatures are non-deterministic so round-tripping through the full
        /// handler can't assert on exact bytes.
        /// </summary>
        internal static byte[] BuildAssertionResponse(
            byte[] credentialId,
            byte[] authData,
            byte[] signature,
            PasskeyRecord? userRecord = null,
            bool uv = false)
        {
            byte[] EncodeUint(ulong v)   { var ww = new CborWriter(); ww.WriteUnsignedInt(v); return ww.Encode(); }
            byte[] EncodeTstr(string s)  { var ww = new CborWriter(); ww.WriteTextString(s); return ww.Encode(); }
            byte[] EncodeBstr(byte[] b)  { var ww = new CborWriter(); ww.WriteByteString(b); return ww.Encode(); }

            // Nested credential descriptor — text keys.
            var descriptor = new CborWriter();
            descriptor.WriteMap(new[]
            {
                (EncodeTstr("id"),   EncodeBstr(credentialId)),
                (EncodeTstr("type"), EncodeTstr("public-key")),
            });
            var descriptorBytes = descriptor.Encode();

            var pairs = new List<(byte[], byte[])>
            {
                (EncodeUint(1), descriptorBytes),
                (EncodeUint(2), EncodeBstr(authData)),
                (EncodeUint(3), EncodeBstr(signature)),
            };

            if (userRecord != null)
            {
                // CTAP 2.1 §6.2: user entity is required for discoverable credentials so
                // the RP can identify which account was asserted. The user.id field is
                // always included; user.name and user.displayName are gated on uv=true
                // (CTAP 2.1 §6.2 PII rule: user-identifiable info MUST NOT be returned
                // without user verification).
                var rawUserHandle = Base64Url.Decode(userRecord.UserHandle);
                var userPairs = new List<(byte[], byte[])>
                {
                    (EncodeTstr("id"), EncodeBstr(rawUserHandle)),
                };
                if (uv)
                {
                    userPairs.Add((EncodeTstr("name"),        EncodeTstr(userRecord.UserName)));
                    userPairs.Add((EncodeTstr("displayName"), EncodeTstr(userRecord.UserDisplayName)));
                }
                var userMap = new CborWriter();
                userMap.WriteMap(userPairs);
                pairs.Add((EncodeUint(4), userMap.Encode()));
            }

            var w = new CborWriter();
            w.WriteMap(pairs);
            return w.Encode();
        }

        // Internal data-transfer object for parsed CTAP2 GetAssertion input.
        private sealed class GetAssertionRequest
        {
            public string       RpId             { get; set; } = string.Empty;
            public byte[]       ClientDataHash   { get; set; } = Array.Empty<byte>();
            public List<byte[]> AllowListCredIds { get; set; } = new List<byte[]>();
            public bool         OptionsUp        { get; set; } = true;
            public bool         OptionsUv        { get; set; } = false;
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
            var requestedAlgs      = new List<int>();
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
                                $"keepasskeywin.makeCredentialRaw: clientDataHash must be 32 bytes, got {clientDataHash.Length}.");
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

                    case 4: // pubKeyCredParams — array of {type, alg}; collect supported alg IDs
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
                                {
                                    // alg is always a negative integer for our supported algs,
                                    // but the CBOR value may be any integer type. Use PeekMajorType
                                    // to handle unsigned (positive) alg IDs gracefully — filter them
                                    // out as unknown rather than throwing.
                                    if (reader.PeekMajorType() == 1)
                                        algId = reader.ReadNegativeInt();
                                    else
                                        reader.SkipValue(); // positive / unknown alg — not supported
                                }
                                else if (field == "type")
                                    paramType = reader.ReadTextString();
                                else
                                    reader.SkipValue();
                            }
                            // Collect only alg IDs we support: -7 (ES256), -257 (RS256).
                            if (paramType == "public-key" && (algId == -7 || algId == -257))
                                requestedAlgs.Add((int)algId.Value);
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
                throw new RpcException(RpcErrorCode.InvalidParams, "keepasskeywin.makeCredentialRaw: missing required CTAP2 key 1 (clientDataHash).");
            if (string.IsNullOrEmpty(rpId))
                throw new RpcException(RpcErrorCode.InvalidParams, "keepasskeywin.makeCredentialRaw: missing required RP id in key 2 (rp map).");
            if (string.IsNullOrEmpty(userHandle))
                throw new RpcException(RpcErrorCode.InvalidParams, "keepasskeywin.makeCredentialRaw: missing required user.id in key 3 (user map).");
            if (string.IsNullOrEmpty(userName))
                throw new RpcException(RpcErrorCode.InvalidParams, "keepasskeywin.makeCredentialRaw: missing required user.name in key 3 (user map).");
            if (requestedAlgs.Count == 0)
                throw new RpcException(RpcErrorCode.UnsupportedAlgorithm,
                    "keepasskeywin.makeCredentialRaw: no supported algorithm found in pubKeyCredParams (supported: -7 ES256, -257 RS256).");

            return new MakeCredentialRequest
            {
                ClientDataHash  = clientDataHash,
                RpId            = rpId!,
                RpName          = string.IsNullOrEmpty(rpName) ? rpId! : rpName!,
                UserHandle      = userHandle!,
                UserName        = userName!,
                UserDisplayName = string.IsNullOrEmpty(userDisplayName) ? userName! : userDisplayName!,
                ExcludeList     = excludeList,
                RequestedAlgs   = requestedAlgs,
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
            public List<int>   RequestedAlgs   { get; set; } = new List<int>();
        }

        // Selects the algorithm to use for a new credential.
        // Tiebreaker: prefer ES256 (-7) over RS256 (-257) when both are offered.
        // ES256 produces smaller COSE_Key blobs (~77 B vs ~270 B for RSA-2048) and
        // smaller signatures. ES256 is what all modern RPs prefer anyway.
        // Falls back to RS256 if ES256 is not in the offered set.
        // Throws UnsupportedAlgorithm if neither supported alg is present.
        private static int SelectAlgorithm(List<int> requestedAlgs)
        {
            if (requestedAlgs.Contains(-7))
                return -7;
            if (requestedAlgs.Contains(-257))
                return -257;
            throw new RpcException(RpcErrorCode.UnsupportedAlgorithm,
                "keepasskeywin.makeCredentialRaw: no supported algorithm found in pubKeyCredParams (supported: -7 ES256, -257 RS256).");
        }

        // Generates a keypair for the given COSE alg ID and returns (pkcs8, coseKeyBytes).
        private static (byte[] pkcs8, byte[] coseKey) GenerateKeyPairAndCoseKey(int algId)
        {
            if (algId == -7)
            {
                var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();
                return (pkcs8, CoseKey.Encode(x, y));
            }
            if (algId == -257)
            {
                var (pkcs8, n, e) = RsaSigner.GenerateKeyPair();
                return (pkcs8, CoseKey.EncodeRsa(n, e));
            }
            throw new RpcException(RpcErrorCode.UnsupportedAlgorithm,
                $"GenerateKeyPairAndCoseKey: unsupported algId {algId}.");
        }

        // Signs data using the stored credential's algorithm.
        private static byte[] SignWithAlgorithm(byte[] pkcs8, byte[] data, int algId)
        {
            if (algId == -7)
                return EcdsaSigner.Sign(pkcs8, data);
            if (algId == -257)
                return RsaSigner.Sign(pkcs8, data);
            throw new RpcException(RpcErrorCode.UnsupportedAlgorithm,
                $"SignWithAlgorithm: unsupported algId {algId}.");
        }

        // keepasskeywin.listCredentials
        // params: { rpId }
        // result: [ { credentialId, userHandle, userName, userDisplayName }, ... ]
        private JToken ListCredentials(JToken? @params)
        {
            var obj  = RequireObject(@params, "keepasskeywin.listCredentials");
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

        // keepasskeywin.signAssertion
        // params: { credentialId, authData (base64), clientDataHash (base64) }
        // result: { signature (base64), authData (base64), userHandle }
        private JToken SignAssertion(JToken? @params)
        {
            var obj             = RequireObject(@params, "keepasskeywin.signAssertion");
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
            var signature = SignWithAlgorithm(pkcs8, signInput, record.AlgId);

            // Build assertion authData (no AT bit, signCount=0).
            var assertionAuthData = AuthDataBuilder.BuildAssertion(record.RpId, userVerified: true);

            return new JObject
            {
                ["signature"]   = Convert.ToBase64String(signature),
                ["authData"]    = Convert.ToBase64String(assertionAuthData),
                ["userHandle"]  = record.UserHandle,
            };
        }

        // keepasskeywin.deleteCredential
        // params: { credentialId }
        // result: { deleted: true|false }
        private JToken DeleteCredential(JToken? @params)
        {
            var obj          = RequireObject(@params, "keepasskeywin.deleteCredential");
            var credentialId = RequireString(obj, "credentialId");

            bool deleted = _store.Delete(credentialId);
            return new JObject { ["deleted"] = deleted };
        }

        // keepasskeywin.enumerateForSync
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
