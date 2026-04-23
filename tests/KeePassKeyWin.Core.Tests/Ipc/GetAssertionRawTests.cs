using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Storage;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    /// <summary>
    /// Tests for the keepasskeywin.getAssertionRaw JSON-RPC method (Phase 4, CTAP 2.1 §6.2).
    /// </summary>
    public class GetAssertionRawTests
    {
        // ── CTAP2 CBOR builders ──────────────────────────────────────────────

        private static byte[] B(byte[] b)  { var w = new CborWriter(); w.WriteByteString(b);  return w.Encode(); }
        private static byte[] T(string s)  { var w = new CborWriter(); w.WriteTextString(s);  return w.Encode(); }
        private static byte[] U(ulong v)   { var w = new CborWriter(); w.WriteUnsignedInt(v); return w.Encode(); }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            var result = new byte[total];
            int offset = 0;
            foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
            return result;
        }

        private static byte[] ArrayOf(params byte[][] items)
        {
            var hdr = new CborWriter();
            hdr.WriteArrayHeader(items.Length);
            return Concat(new[] { hdr.Encode() }.Concat(items).ToArray());
        }

        private static byte[] EmptyArray()
        {
            var w = new CborWriter(); w.WriteArrayHeader(0); return w.Encode();
        }

        private static byte[] MapOf(params (byte[] key, byte[] value)[] pairs)
        {
            var w = new CborWriter(); w.WriteMap(pairs); return w.Encode();
        }

        /// <summary>
        /// Builds a credential descriptor {type: "public-key", id: bstr}.
        /// </summary>
        private static byte[] Descriptor(byte[] credIdRaw, string type = "public-key")
            => MapOf(
                (T("id"),   B(credIdRaw)),
                (T("type"), T(type)));

        /// <summary>
        /// Builds a CTAP2 GetAssertion request with the provided allowList credentials
        /// and optional bool options (up/uv). Since CborWriter has no bool primitive,
        /// we manually assemble the `options` map when requested.
        /// </summary>
        private static byte[] BuildGetAssertionCbor(
            string rpId,
            byte[]? clientDataHash = null,
            IEnumerable<byte[]>? allowListCredIds = null,
            bool includeAllowList = true,
            bool? optUp = null,
            bool? optUv = null,
            IEnumerable<byte[]>? rawDescriptors = null)
        {
            clientDataHash ??= new byte[32];

            byte[]? allowListEncoded = null;
            if (includeAllowList)
            {
                var descriptors = new List<byte[]>();
                if (rawDescriptors != null)
                {
                    descriptors.AddRange(rawDescriptors);
                }
                else if (allowListCredIds != null)
                {
                    foreach (var id in allowListCredIds)
                        descriptors.Add(Descriptor(id));
                }
                allowListEncoded = ArrayOf(descriptors.ToArray());
            }

            var pairs = new List<(byte[] key, byte[] value)>
            {
                (U(1), T(rpId)),
                (U(2), B(clientDataHash)),
            };
            if (allowListEncoded != null)
                pairs.Add((U(3), allowListEncoded));

            if (optUp.HasValue || optUv.HasValue)
            {
                // CborWriter doesn't emit bools natively — assemble options map by hand.
                // options map shape: { "up": bool, "uv": bool }. Keys sort "up" < "uv"
                // (both start with 0x62, second byte 0x75, differ at third: 0x70<0x76).
                var opt = new List<(byte[] key, byte[] value)>();
                if (optUp.HasValue) opt.Add((T("up"), new[] { optUp.Value ? (byte)0xF5 : (byte)0xF4 }));
                if (optUv.HasValue) opt.Add((T("uv"), new[] { optUv.Value ? (byte)0xF5 : (byte)0xF4 }));
                var ow = new CborWriter(); ow.WriteMap(opt);
                pairs.Add((U(5), ow.Encode()));
            }

            var w = new CborWriter();
            w.WriteMap(pairs);
            return w.Encode();
        }

        // ── Handler factory & stored-record helper ───────────────────────────

        private static VaultHandler MakeHandler(out InMemoryPasskeyStore store)
        {
            store = new InMemoryPasskeyStore();
            return new VaultHandler(store);
        }

        /// <summary>
        /// Populates the store with a fresh P-256 credential and returns the raw
        /// credentialId bytes plus the record (including PKCS#8 private key).
        /// </summary>
        private static (byte[] rawCredId, PasskeyRecord record) SeedCredential(
            IPasskeyStore store, string rpId = "example.com")
        {
            var (pkcs8, x, y) = KeePassKeyWin.Core.Crypto.EcdsaSigner.GenerateKeyPair();
            var rawCredId = new byte[32];
            new Random(1337).NextBytes(rawCredId);
            var credentialId = Base64Url.Encode(rawCredId);
            var record = new PasskeyRecord
            {
                CredentialId    = credentialId,
                RpId            = rpId,
                RpName          = rpId,
                UserHandle      = Base64Url.Encode(new byte[] { 0x01, 0x02, 0x03 }),
                UserName        = "alice",
                UserDisplayName = "Alice",
                AlgId           = -7,
                PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
                PublicKeyCose   = KeePassKeyWin.Core.Cbor.CoseKey.Encode(x, y),
                SignCount       = 0,
            };
            store.Add(record);
            return (rawCredId, record);
        }

        private static JObject CallGetAssertionRaw(VaultHandler handler, byte[] cborBytes, bool uv = false)
        {
            var result = handler.Handle("keepasskeywin.getAssertionRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(cborBytes),
                ["uv"]   = uv,
            });
            return (JObject)result!;
        }

        // ── Request-parser coverage ──────────────────────────────────────────

        [Fact]
        public void Parser_HappyPath_SelectsCredential()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
            var result = CallGetAssertionRaw(handler, req, uv: true);

            Assert.NotNull(result["cbor"]?.Value<string>());
        }

        [Fact]
        public void EmptyAllowList_NoCredentialForRp_ThrowsCredentialNotFound()
        {
            // Empty allowList = discoverable flow; no credential seeded → CredentialNotFound.
            var handler = MakeHandler(out _);
            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>());

            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void AllowListOnlyUnsupportedTypes_ThrowsCredentialNotFound()
        {
            // Descriptor with type != "public-key" is silently dropped. The resulting
            // empty credential list triggers the discoverable flow (CTAP 2.1 §6.2).
            // No credential seeded → CredentialNotFound.
            // Note: if a credential were seeded for "example.com", the unsupported
            // descriptor would be silently bypassed and the discoverable flow would
            // succeed — by design, filtering unknown types falls back to discoverable.
            var handler = MakeHandler(out _);
            var badDescriptor = MapOf(
                (T("id"),   B(new byte[] { 0x01 })),
                (T("type"), T("symmetric")));
            var req = BuildGetAssertionCbor("example.com", rawDescriptors: new[] { badDescriptor });

            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void AllowListNoMatch_ThrowsNoCredentials()
        {
            var handler = MakeHandler(out var store);
            SeedCredential(store);
            var unrelated = new byte[32]; unrelated[0] = 0xFF;

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { unrelated });
            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void OptionsUpFalse_ThrowsInvalidOption()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor(
                "example.com",
                allowListCredIds: new[] { rawCredId },
                optUp: false);

            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.InvalidOption, ex.Code);
        }

        [Fact]
        public void OptionsUpTrue_Succeeds()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor(
                "example.com",
                allowListCredIds: new[] { rawCredId },
                optUp: true,
                optUv: true);

            var result = CallGetAssertionRaw(handler, req, uv: true);
            Assert.NotNull(result["cbor"]?.Value<string>());
        }

        [Fact]
        public void AbsentAllowList_NoCredentialForRp_ThrowsCredentialNotFound()
        {
            // Absent key 3 = discoverable flow (CTAP 2.1 §6.2); no credential seeded → CredentialNotFound.
            var handler = MakeHandler(out _);
            var req = BuildGetAssertionCbor("example.com", includeAllowList: false);

            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void MissingClientDataHash_ThrowsInvalidParams()
        {
            // Hand-build a request without key 2.
            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(1), T("example.com")),
                (U(3), ArrayOf(Descriptor(new byte[] { 0x01 }))),
            });

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                CallGetAssertionRaw(handler, w.Encode()));
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void MissingRpId_ThrowsInvalidParams()
        {
            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(2), B(new byte[32])),
                (U(3), ArrayOf(Descriptor(new byte[] { 0x01 }))),
            });

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                CallGetAssertionRaw(handler, w.Encode()));
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void ShortClientDataHash_ThrowsInvalidParams()
        {
            var req = BuildGetAssertionCbor("example.com",
                clientDataHash: new byte[16],
                allowListCredIds: new[] { new byte[] { 0xAB } });

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void DispatchTable_GetAssertionRaw_IsRouted()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.getAssertionRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0x00 }), // uint 0, not a map
                    ["uv"]   = false,
                }));
            Assert.NotEqual(RpcErrorCode.MethodNotFound, ex.Code);
        }

        // ── Discoverable credential flow ─────────────────────────────────────

        [Fact]
        public void Discoverable_EmptyAllowList_OneCredential_Succeeds()
        {
            // Empty allowList + credential present → assertion succeeds.
            var handler = MakeHandler(out var store);
            SeedCredential(store, "example.com");

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>(), optUv: true);
            var result = CallGetAssertionRaw(handler, req, uv: true);

            Assert.NotNull(result["cbor"]?.Value<string>());
        }

        [Fact]
        public void Discoverable_EmptyAllowList_NoMatch_ThrowsCredentialNotFound()
        {
            // Empty allowList + no credential for rpId → CredentialNotFound.
            var handler = MakeHandler(out var store);
            SeedCredential(store, "other.com"); // wrong RP

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>());
            var ex = Assert.Throws<RpcException>(() => CallGetAssertionRaw(handler, req));
            Assert.Equal(RpcErrorCode.CredentialNotFound, ex.Code);
        }

        [Fact]
        public void Discoverable_AbsentKey3_TreatedAsDiscoverable_Succeeds()
        {
            // Absent key 3 (includeAllowList: false) = discoverable flow.
            var handler = MakeHandler(out var store);
            SeedCredential(store, "example.com");

            var req = BuildGetAssertionCbor("example.com", includeAllowList: false, optUv: true);
            var result = CallGetAssertionRaw(handler, req, uv: true);

            Assert.NotNull(result["cbor"]?.Value<string>());
        }

        [Fact]
        public void Discoverable_UserEntityKey4_PresentInResponseCbor_WithUv()
        {
            // When discoverable + uv=true, response must contain CTAP2 key 4 (user entity)
            // with id, name, and displayName.
            var handler = MakeHandler(out var store);
            SeedCredential(store, "example.com");

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>(), optUv: true);
            var result = CallGetAssertionRaw(handler, req, uv: true);

            var responseBytes = Convert.FromBase64String(result["cbor"]!.Value<string>()!);
            var (credId, authData, signature, userEntity) = DecodeAssertionResponseFull(responseBytes);

            Assert.NotNull(userEntity);
            Assert.NotNull(userEntity!.Id);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, userEntity.Id); // matches SeedCredential's UserHandle
            Assert.Equal("alice",  userEntity.Name);
            Assert.Equal("Alice",  userEntity.DisplayName);
        }

        [Fact]
        public void Discoverable_UserEntityKey4_IdOnly_WhenUvFalse()
        {
            // CTAP 2.1 §6.2 PII rule: without uv, user.name and user.displayName must not
            // be included. Only user.id is mandatory.
            var handler = MakeHandler(out var store);
            SeedCredential(store, "example.com");

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>());
            var result = CallGetAssertionRaw(handler, req, uv: false);

            var responseBytes = Convert.FromBase64String(result["cbor"]!.Value<string>()!);
            var (_, _, _, userEntity) = DecodeAssertionResponseFull(responseBytes);

            Assert.NotNull(userEntity);
            Assert.NotNull(userEntity!.Id);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, userEntity.Id);
            Assert.Null(userEntity.Name);         // PII suppressed without UV
            Assert.Null(userEntity.DisplayName);   // PII suppressed without UV
        }

        [Fact]
        public void Discoverable_UserEntityKey4_HexShape_IntKeyFour()
        {
            // Hex-shape canary: verify BuildAssertionResponse emits CTAP2 key 4 when
            // userRecord is non-null, uv=true. Uses fixed inputs so byte offsets are
            // predictable. ECDSA is non-deterministic so we call the static encoder directly.
            byte[] credId    = new byte[] { 0xA0, 0xA1 };
            byte[] authData  = new byte[] { 0xB0 };
            byte[] signature = new byte[] { 0xC0 };

            var userHandle   = new byte[] { 0xD0, 0xD1 };
            var userRecord   = new PasskeyRecord
            {
                UserHandle      = Base64Url.Encode(userHandle),
                UserName        = "bob",
                UserDisplayName = "Bob",
            };

            var bytes = VaultHandler.BuildAssertionResponse(credId, authData, signature, userRecord, uv: true);

            // Top-level map must have 4 pairs: 0xA4.
            Assert.Equal(0xA4, bytes[0]);

            // Parse the response and verify key 4 is present.
            var (_, _, _, userEntity) = DecodeAssertionResponseFull(bytes);
            Assert.NotNull(userEntity);
            Assert.Equal(userHandle, userEntity!.Id);
            Assert.Equal("bob", userEntity.Name);
            Assert.Equal("Bob", userEntity.DisplayName);
        }

        [Fact]
        public void Discoverable_SignCount_IncrementedEvenInDiscoverableFlow()
        {
            // IncrementSignCount must be called for discoverable credentials just as
            // for allowList-driven assertions.
            var handler = MakeHandler(out var store);
            var (_, record) = SeedCredential(store, "example.com");
            Assert.Equal(0u, record.SignCount);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: Array.Empty<byte[]>(), optUv: true);
            CallGetAssertionRaw(handler, req, uv: true);

            Assert.Equal(1u, store.FindById(record.CredentialId)!.SignCount);
        }

        // ── SignCount increment + return shape ───────────────────────────────

        [Fact]
        public void SignCount_IncrementedToOne_OnFirstAssertion()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, record) = SeedCredential(store);
            Assert.Equal(0u, record.SignCount);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
            var result = CallGetAssertionRaw(handler, req, uv: true);

            // After one assertion, signCount should be 1.
            var authData = ExtractAuthDataFromResponse(result);
            var signCountBe = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);
            Assert.Equal(1u, signCountBe);
            Assert.Equal(1u, store.FindById(record.CredentialId)!.SignCount);
        }

        [Fact]
        public void SignCount_MonotonicAcrossAssertions()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            uint[] observed = new uint[5];
            for (int i = 0; i < 5; i++)
            {
                var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
                var result = CallGetAssertionRaw(handler, req);
                var authData = ExtractAuthDataFromResponse(result);
                observed[i] = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);
            }

            Assert.Equal(new uint[] { 1, 2, 3, 4, 5 }, observed);
        }

        // ── SignCount concurrency (in-memory store only) ─────────────────────

        [Fact]
        public void SignCount_ConcurrentIncrement_NoLostUpdates()
        {
            var store = new InMemoryPasskeyStore();
            var rec = new PasskeyRecord { CredentialId = "cred-concur", RpId = "x", UserName = "u", UserHandle = "h", SignCount = 0 };
            store.Add(rec);

            const int threadCount = 100;
            Parallel.For(0, threadCount, _ => store.IncrementSignCount("cred-concur"));

            Assert.Equal((uint)threadCount, store.FindById("cred-concur")!.SignCount);
        }

        [Fact]
        public void IncrementSignCount_MissingCredential_Throws()
        {
            var store = new InMemoryPasskeyStore();
            Assert.Throws<KeyNotFoundException>(() => store.IncrementSignCount("never-added"));
        }

        // ── authData flags ───────────────────────────────────────────────────

        [Fact]
        public void AssertionAuthData_FlagsUpOnly_WhenUvFalse()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
            var result = CallGetAssertionRaw(handler, req, uv: false);

            var authData = ExtractAuthDataFromResponse(result);
            byte flags = authData[32];
            Assert.Equal(0x01, flags); // UP only; no UV, no AT
        }

        [Fact]
        public void AssertionAuthData_FlagsUpAndUv_WhenUvTrue()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
            var result = CallGetAssertionRaw(handler, req, uv: true);

            var authData = ExtractAuthDataFromResponse(result);
            byte flags = authData[32];
            Assert.Equal(0x05, flags); // UP | UV, no AT
        }

        [Fact]
        public void AssertionAuthData_Length37_NoAtBit()
        {
            var handler = MakeHandler(out var store);
            var (rawCredId, _) = SeedCredential(store);

            var req = BuildGetAssertionCbor("example.com", allowListCredIds: new[] { rawCredId });
            var result = CallGetAssertionRaw(handler, req, uv: true);

            var authData = ExtractAuthDataFromResponse(result);
            Assert.Equal(37, authData.Length);
            Assert.Equal(0, authData[32] & 0x40);
        }

        /// <summary>
        /// Populates the store with a fresh RSA-2048 credential and returns the raw
        /// credentialId bytes plus the record (including PKCS#8 private key).
        /// </summary>
        private static (byte[] rawCredId, PasskeyRecord record) SeedRs256Credential(
            IPasskeyStore store, string rpId = "example.com")
        {
            var (pkcs8, n, e) = KeePassKeyWin.Core.Crypto.RsaSigner.GenerateKeyPair();
            var rawCredId = new byte[32];
            new Random(7331).NextBytes(rawCredId);
            var credentialId = Base64Url.Encode(rawCredId);
            var rsaCoseKey = KeePassKeyWin.Core.Cbor.CoseKey.EncodeRsa(n, e);
            var record = new PasskeyRecord
            {
                CredentialId    = credentialId,
                RpId            = rpId,
                RpName          = rpId,
                UserHandle      = Base64Url.Encode(new byte[] { 0x04, 0x05, 0x06 }),
                UserName        = "bob",
                UserDisplayName = "Bob",
                AlgId           = -257,
                PrivateKeyPkcs8 = Convert.ToBase64String(pkcs8),
                PublicKeyCose   = rsaCoseKey,
                SignCount       = 0,
            };
            store.Add(record);
            return (rawCredId, record);
        }

        // ── Round-trip: register then sign → ECDSA verify ────────────────────

        [Fact]
        public void MakeCredentialThenGetAssertion_RoundTripECDSASignatureVerifies()
        {
            var handler = MakeHandler(out var store);
            var rpId = "example.com";

            // 1. MakeCredential
            var mcReq = BuildMinimalMakeCredentialCborForRound(rpId, userId: new byte[] { 0xAA });
            var mcResult = (JObject)handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(mcReq),
                ["uv"]   = true,
            })!;
            var credIdB64Url = mcResult["credentialIdB64Url"]!.Value<string>()!;
            Assert.False(string.IsNullOrEmpty(credIdB64Url));

            // 2. Build GetAssertion request with this credId in the allowList.
            var rawCredId = Base64Url.Decode(credIdB64Url);
            var clientDataHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\"}"));
            var gaReq = BuildGetAssertionCbor(rpId,
                clientDataHash: clientDataHash,
                allowListCredIds: new[] { rawCredId });

            var gaResult = CallGetAssertionRaw(handler, gaReq, uv: true);

            // 3. Decode response — assert structural contract first.
            var gaResponseBytes = Convert.FromBase64String(gaResult["cbor"]!.Value<string>()!);
            var (respCredId, authData, signature) = DecodeAssertionResponse(gaResponseBytes);

            Assert.Equal(rawCredId, respCredId);
            Assert.Equal(37, authData.Length);
            var expectedRpIdHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rpId));
            Assert.Equal(expectedRpIdHash, authData[..32]);
            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP must be set");
            Assert.True((flags & 0x04) != 0, "UV must be set when uv=true");
            Assert.True((flags & 0x40) == 0, "AT must NOT be set for assertion authData");
            var signCountBe = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);
            Assert.Equal(1u, signCountBe);

            // 4. ECDSA-verify using the public key EXTRACTED FROM THE ATTESTATION OBJECT
            // (not the store). This is strictly stronger: it catches a class of bug
            // where the attestation embeds a wrong COSE_Key while the store has the
            // right one. The Phase 3 CTAP2-vs-WebAuthn landmine lives in this shape.
            byte[] attCoseKeyBytes = ExtractCoseKeyFromAttestationObject(Convert.FromBase64String(mcResult["cbor"]!.Value<string>()!));
            var stored = store.FindById(credIdB64Url)!;
            Assert.Equal(stored.PublicKeyCose, attCoseKeyBytes);  // sanity check: attestation key and stored key agree
            var (curveX, curveY) = DecodeCoseKeyXY(attCoseKeyBytes);

            using var pubKey = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = curveX, Y = curveY },
            });

            var signInput = Concat(authData, clientDataHash);
            bool ok = pubKey.VerifyData(signInput, signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            Assert.True(ok, "ECDSA signature over authData || clientDataHash must verify with the MakeCredential-returned public key.");
        }

        [Fact]
        public void Rs256Credential_GetAssertion_RoundTripSignatureVerifies()
        {
            // Seed a pre-generated RS256 credential (AlgId=-257) directly into the store,
            // bypassing makeCredentialRaw. This exercises the full HandleGetAssertionRaw
            // dispatch path for RS256 — specifically that SignWithAlgorithm routes to
            // RsaSigner.Sign rather than EcdsaSigner.Sign.
            var handler = MakeHandler(out var store);
            var rpId = "example.com";

            var (rawCredId, record) = SeedRs256Credential(store, rpId);

            var clientDataHash = SHA256.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes("{\"type\":\"webauthn.get\",\"alg\":\"RS256\"}"));
            var gaReq = BuildGetAssertionCbor(rpId,
                clientDataHash: clientDataHash,
                allowListCredIds: new[] { rawCredId });

            var gaResult = CallGetAssertionRaw(handler, gaReq, uv: true);

            var gaResponseBytes = Convert.FromBase64String(gaResult["cbor"]!.Value<string>()!);
            var (respCredId, authData, signature) = DecodeAssertionResponse(gaResponseBytes);

            // Response must identify the right credential.
            Assert.Equal(rawCredId, respCredId);

            // authData is 37 bytes (assertion, no AT flag).
            Assert.Equal(37, authData.Length);

            // rpIdHash at [0..32].
            var expectedRpIdHash = SHA256.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(rpId));
            Assert.Equal(expectedRpIdHash, authData[..32]);

            // UP+UV flags set, AT not set.
            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP must be set");
            Assert.True((flags & 0x04) != 0, "UV must be set when uv=true");
            Assert.True((flags & 0x40) == 0, "AT must NOT be set for assertion authData");

            // signCount incremented to 1.
            var signCountBe = (uint)((authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]);
            Assert.Equal(1u, signCountBe);

            // RS256 signature is exactly 256 bytes (2048-bit modulus).
            Assert.Equal(256, signature.Length);

            // Verify RSA-PKCS1-v1_5 signature over authData || clientDataHash.
            var coseKeyBytes = record.PublicKeyCose!;
            var (parsedN, parsedE) = DecodeCoseKeyNE(coseKeyBytes);

            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = parsedN, Exponent = parsedE });
            var signInput = Concat(authData, clientDataHash);
            bool ok = rsa.VerifyData(signInput, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(ok, "RS256 signature over authData || clientDataHash must verify with the stored public key.");
        }

        // ── Response-shape hex test (Phase 3 landmine canary) ────────────────
        //
        // ECDSA signatures are non-deterministic, so we can't freeze an exact
        // handler-produced byte stream. Instead, call the factored-out encoder
        // (BuildAssertionResponse) with fixed inputs and assert byte-by-byte
        // on the CTAP2-canonical shape.
        //
        // CTAP2 §6.2 response: integer-keyed top-level map.
        //   1: PublicKeyCredentialDescriptor (text-keyed: id, type)
        //   2: authData (bstr)
        //   3: signature (bstr)
        // Integer keys 1,2,3 encode to single bytes 0x01,0x02,0x03 — natural sort order.
        // Nested descriptor keys: "id" = 62 69 64, "type" = 64 74 79 70 65; "id" sorts FIRST.

        [Fact]
        public void ResponseShape_HexLevelAssertion_IntegerTopLevelTextNested()
        {
            // Fixed, tiny inputs so every byte offset is predictable.
            byte[] credId    = new byte[] { 0xA0, 0xA1, 0xA2 };      // 3 bytes
            byte[] authData  = new byte[] { 0xB0, 0xB1 };             // 2 bytes
            byte[] signature = new byte[] { 0xC0, 0xC1, 0xC2, 0xC3 }; // 4 bytes

            var bytes = VaultHandler.BuildAssertionResponse(credId, authData, signature);

            // Expected top-level: 0xA3 (map, 3 pairs).
            Assert.Equal(0xA3, bytes[0]);

            // Pair 1: key = 0x01 (uint 1).
            Assert.Equal(0x01, bytes[1]);
            // Value = nested descriptor map, 2 pairs: 0xA2.
            Assert.Equal(0xA2, bytes[2]);

            // Nested-descriptor pair 1: tstr "id" (0x62 0x69 0x64), sorts FIRST.
            Assert.Equal(0x62, bytes[3]);
            Assert.Equal(0x69, bytes[4]);
            Assert.Equal(0x64, bytes[5]);
            // Then bstr credId: 0x43 (mt 2, len 3), 0xA0 A1 A2.
            Assert.Equal(0x43, bytes[6]);
            Assert.Equal(0xA0, bytes[7]);
            Assert.Equal(0xA1, bytes[8]);
            Assert.Equal(0xA2, bytes[9]);

            // Nested-descriptor pair 2: tstr "type" (0x64 0x74 0x79 0x70 0x65).
            Assert.Equal(0x64, bytes[10]);
            Assert.Equal(0x74, bytes[11]);
            Assert.Equal(0x79, bytes[12]);
            Assert.Equal(0x70, bytes[13]);
            Assert.Equal(0x65, bytes[14]);
            // Value tstr "public-key" = 0x6A then ASCII bytes.
            Assert.Equal(0x6A, bytes[15]);
            // "public-key" = 70 75 62 6C 69 63 2D 6B 65 79
            var publicKey = Encoding.ASCII.GetBytes("public-key");
            for (int i = 0; i < publicKey.Length; i++)
                Assert.Equal(publicKey[i], bytes[16 + i]);

            int pos = 16 + publicKey.Length; // 26

            // Pair 2: key = 0x02 (uint 2).
            Assert.Equal(0x02, bytes[pos++]);
            // Value = bstr authData (2 bytes) → 0x42 B0 B1.
            Assert.Equal(0x42, bytes[pos++]);
            Assert.Equal(0xB0, bytes[pos++]);
            Assert.Equal(0xB1, bytes[pos++]);

            // Pair 3: key = 0x03 (uint 3).
            Assert.Equal(0x03, bytes[pos++]);
            // Value = bstr signature (4 bytes) → 0x44 C0 C1 C2 C3.
            Assert.Equal(0x44, bytes[pos++]);
            Assert.Equal(0xC0, bytes[pos++]);
            Assert.Equal(0xC1, bytes[pos++]);
            Assert.Equal(0xC2, bytes[pos++]);
            Assert.Equal(0xC3, bytes[pos++]);

            Assert.Equal(bytes.Length, pos);
        }

        // ── MakeCredential extended-response assertions (new fields) ─────────

        [Fact]
        public void MakeCredential_ExtendedResponse_IncludesRpAndUserFields()
        {
            var handler = MakeHandler(out _);
            var cbor = BuildMinimalMakeCredentialCborForRound(
                rpId: "relying-party.example",
                userId: Encoding.UTF8.GetBytes("user-handle-raw"),
                userName: "bob@example.com",
                userDisplayName: "Bob Smith",
                rpName: "Relying Party");

            var result = (JObject)handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(cbor),
                ["uv"]   = false,
            })!;

            Assert.NotNull(result["credentialIdB64Url"]?.Value<string>());
            Assert.Equal("relying-party.example", result["rpId"]?.Value<string>());
            Assert.Equal("Relying Party",         result["rpName"]?.Value<string>());
            Assert.Equal(Base64Url.Encode(Encoding.UTF8.GetBytes("user-handle-raw")),
                         result["userHandleB64Url"]?.Value<string>());
            Assert.Equal("bob@example.com",       result["userName"]?.Value<string>());
            Assert.Equal("Bob Smith",             result["userDisplayName"]?.Value<string>());
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        /// <summary>Parsed user entity from a CTAP2 GetAssertion response key 4.</summary>
        private sealed class ParsedUserEntity
        {
            public byte[]?  Id          { get; set; }
            public string?  Name        { get; set; }
            public string?  DisplayName { get; set; }
        }

        private static byte[] ExtractAuthDataFromResponse(JObject result)
        {
            var cborB64 = result["cbor"]!.Value<string>()!;
            var decoded = Convert.FromBase64String(cborB64);
            var (_, authData, _, _) = DecodeAssertionResponseFull(decoded);
            return authData;
        }

        /// <summary>Decodes a CTAP2 GetAssertion response map into its three mandatory fields.</summary>
        private static (byte[] credId, byte[] authData, byte[] signature) DecodeAssertionResponse(byte[] bytes)
        {
            var (credId, authData, signature, _) = DecodeAssertionResponseFull(bytes);
            return (credId, authData, signature);
        }

        /// <summary>
        /// Decodes a CTAP2 GetAssertion response map into its three mandatory fields
        /// plus the optional user entity (key 4), which is null if absent.
        /// </summary>
        private static (byte[] credId, byte[] authData, byte[] signature, ParsedUserEntity? userEntity)
            DecodeAssertionResponseFull(byte[] bytes)
        {
            var reader = new CborReader(bytes);
            int count = reader.ReadMapHeader();
            byte[]? credId = null, authData = null, signature = null;
            ParsedUserEntity? userEntity = null;

            for (int i = 0; i < count; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                switch (key)
                {
                    case 1:
                    {
                        int nested = reader.ReadMapHeader();
                        for (int k = 0; k < nested; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "id")
                                credId = reader.ReadByteString();
                            else if (field == "type")
                                reader.ReadTextString(); // ignore
                            else
                                reader.SkipValue();
                        }
                        break;
                    }
                    case 2:
                        authData = reader.ReadByteString();
                        break;
                    case 3:
                        signature = reader.ReadByteString();
                        break;
                    case 4:
                    {
                        // User entity: text-keyed map with "id" (bstr), optional "name" and "displayName".
                        userEntity = new ParsedUserEntity();
                        int nested = reader.ReadMapHeader();
                        for (int k = 0; k < nested; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "id")
                                userEntity.Id = reader.ReadByteString();
                            else if (field == "name")
                                userEntity.Name = reader.ReadTextString();
                            else if (field == "displayName")
                                userEntity.DisplayName = reader.ReadTextString();
                            else
                                reader.SkipValue();
                        }
                        break;
                    }
                    default:
                        reader.SkipValue();
                        break;
                }
            }
            Assert.NotNull(credId);
            Assert.NotNull(authData);
            Assert.NotNull(signature);
            return (credId!, authData!, signature!, userEntity);
        }

        /// <summary>
        /// Decodes a CTAP2 MakeCredential attestation object (integer-keyed
        /// {1:fmt, 2:authData, 3:attStmt}) and returns the trailing COSE_Key
        /// CBOR embedded in <c>authData</c>.
        ///
        /// AuthData layout (WebAuthn L3 §6.5.1):
        ///   [0..32]    rpIdHash           (SHA-256)
        ///   [32]       flags
        ///   [33..37]   signCount (uint32 BE)
        ///   [37..53]   AAGUID (16 bytes)
        ///   [53..55]   credIdLen (uint16 BE)
        ///   [55..55+L] credentialId
        ///   [...]      credentialPublicKey (COSE_Key CBOR, variable length) — tail
        /// </summary>
        private static byte[] ExtractCoseKeyFromAttestationObject(byte[] attestationObject)
        {
            var reader = new CborReader(attestationObject);
            int count = reader.ReadMapHeader();
            byte[]? authData = null;
            for (int i = 0; i < count; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                if (key == 2) authData = reader.ReadByteString();
                else reader.SkipValue();
            }
            Assert.NotNull(authData);

            int credIdLen = (authData![53] << 8) | authData[54];
            int coseStart = 55 + credIdLen;
            int coseLen   = authData.Length - coseStart;
            var cose = new byte[coseLen];
            Array.Copy(authData, coseStart, cose, 0, coseLen);
            return cose;
        }

        /// <summary>
        /// Extracts the RSA modulus (n, COSE key -1) and exponent (e, COSE key -2)
        /// from an RS256 COSE_Key CBOR blob (RFC 8230 §4).
        /// </summary>
        private static (byte[] n, byte[] e) DecodeCoseKeyNE(byte[] coseKey)
        {
            var reader = new CborReader(coseKey);
            int count = reader.ReadMapHeader();
            byte[]? n = null, e = null;
            for (int i = 0; i < count; i++)
            {
                int peek = reader.PeekMajorType();
                long key;
                if (peek == 0) { key = (long)reader.ReadUnsignedInt(); reader.SkipValue(); continue; }
                else           key = reader.ReadNegativeInt();

                if (key == -1)      n = reader.ReadByteString();
                else if (key == -2) e = reader.ReadByteString();
                else                reader.SkipValue();
            }
            Assert.NotNull(n); Assert.NotNull(e);
            return (n!, e!);
        }

        /// <summary>Extracts the 32-byte X and Y coordinates from a COSE_Key CBOR blob.</summary>
        private static (byte[] x, byte[] y) DecodeCoseKeyXY(byte[] coseKey)
        {
            var reader = new CborReader(coseKey);
            int count = reader.ReadMapHeader();
            byte[]? x = null, y = null;
            for (int i = 0; i < count; i++)
            {
                int peek = reader.PeekMajorType();
                long key;
                if (peek == 0) key = (long)reader.ReadUnsignedInt();
                else           key = reader.ReadNegativeInt();

                if (key == -2) x = reader.ReadByteString();
                else if (key == -3) y = reader.ReadByteString();
                else reader.SkipValue();
            }
            Assert.NotNull(x); Assert.NotNull(y);
            Assert.Equal(32, x!.Length);
            Assert.Equal(32, y!.Length);
            return (x!, y!);
        }

        private static byte[] BuildMinimalMakeCredentialCborForRound(
            string rpId,
            byte[] userId,
            string rpName = "Example RP",
            string userName = "alice",
            string userDisplayName = "Alice")
        {
            var clientDataHash = new byte[32];

            var rpMap = MapOf(
                (T("id"),   T(rpId)),
                (T("name"), T(rpName)));

            var userMap = MapOf(
                (T("id"),          B(userId)),
                (T("name"),        T(userName)),
                (T("displayName"), T(userDisplayName)));

            var algEntry = MapOf(
                (T("type"), T("public-key")),
                (T("alg"),  N(-7)));

            var pkParams = ArrayOf(algEntry);

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(1), B(clientDataHash)),
                (U(2), rpMap),
                (U(3), userMap),
                (U(4), pkParams),
                (U(5), EmptyArray()),
            });
            return w.Encode();
        }

        private static byte[] N(long v)   { var w = new CborWriter(); w.WriteNegativeInt(v); return w.Encode(); }
    }
}
