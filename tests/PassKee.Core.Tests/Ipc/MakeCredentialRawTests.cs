using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using PassKee.Core.Cbor;
using PassKee.Core.Ipc;
using PassKee.Core.Storage;
using Xunit;

namespace PassKee.Core.Tests.Ipc
{
    /// <summary>
    /// Tests for the passkee.makeCredentialRaw JSON-RPC method (Phase 3 Track 2).
    /// </summary>
    public class MakeCredentialRawTests
    {
        // ── CTAP2 CBOR builders ──────────────────────────────────────────────

        private static byte[] B(byte[] b)  { var w = new CborWriter(); w.WriteByteString(b);  return w.Encode(); }
        private static byte[] T(string s)  { var w = new CborWriter(); w.WriteTextString(s);  return w.Encode(); }
        private static byte[] U(ulong v)   { var w = new CborWriter(); w.WriteUnsignedInt(v); return w.Encode(); }
        private static byte[] N(long v)    { var w = new CborWriter(); w.WriteNegativeInt(v); return w.Encode(); }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            var result = new byte[total];
            int offset = 0;
            foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
            return result;
        }

        // Builds a CBOR array header followed by pre-encoded item bytes.
        private static byte[] ArrayOf(params byte[][] items)
        {
            var hdr = new CborWriter();
            hdr.WriteArrayHeader(items.Length);
            var headerBytes = hdr.Encode();
            return Concat(new[] { headerBytes }.Concat(items).ToArray());
        }

        private static byte[] EmptyArray()
        {
            var w = new CborWriter(); w.WriteArrayHeader(0); return w.Encode();
        }

        private static byte[] EmptyMap()
        {
            var w = new CborWriter(); w.WriteMap(Array.Empty<(byte[], byte[])>()); return w.Encode();
        }

        /// <summary>
        /// Encodes a map whose keys and values are supplied as interleaved pre-encoded byte arrays.
        /// Pairs are (key, value) in the order given; CborWriter sorts by key.
        /// </summary>
        private static byte[] MapOf(params (byte[] key, byte[] value)[] pairs)
        {
            var w = new CborWriter();
            w.WriteMap(pairs);
            return w.Encode();
        }

        /// <summary>
        /// Builds a minimal but structurally valid CTAP2 authenticatorMakeCredential input map.
        /// Only ES256 (-7) in pubKeyCredParams, empty excludeList.
        /// </summary>
        private static byte[] BuildMinimalMakeCredentialCbor(
            string rpId = "example.com",
            byte[]? userId = null,
            string userName = "user@example.com",
            IEnumerable<byte[]>? excludeList = null)
        {
            var clientDataHash = new byte[32];     // 32 zero bytes
            userId ??= new byte[16];               // 16 zero bytes

            var rpMap = MapOf(
                (T("id"),   T(rpId)),
                (T("name"), T("Example RP")));

            var userMap = MapOf(
                (T("id"),          B(userId)),
                (T("name"),        T(userName)),
                (T("displayName"), T("Display Name")));

            var algEntry = MapOf(
                (T("type"), T("public-key")),
                (T("alg"),  N(-7)));

            var pubKeyCredParams = ArrayOf(algEntry);

            byte[] exList;
            if (excludeList == null)
            {
                exList = EmptyArray();
            }
            else
            {
                var descriptors = new List<byte[]>();
                foreach (var id in excludeList)
                    descriptors.Add(MapOf((T("id"), B(id)), (T("type"), T("public-key"))));
                exList = ArrayOf(descriptors.ToArray());
            }

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(1), B(clientDataHash)),
                (U(2), rpMap),
                (U(3), userMap),
                (U(4), pubKeyCredParams),
                (U(5), exList),
            });
            return w.Encode();
        }

        // ── Handler factory ──────────────────────────────────────────────────

        private static VaultHandler MakeHandler(out InMemoryPasskeyStore store)
        {
            store = new InMemoryPasskeyStore();
            return new VaultHandler(store);
        }

        private static JObject CallMakeCredentialRaw(VaultHandler handler, byte[] cborBytes, bool uv = false)
        {
            var result = handler.Handle("passkee.makeCredentialRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(cborBytes),
                ["uv"]   = uv,
            });
            return (JObject)result!;
        }

        // ── Happy path ───────────────────────────────────────────────────────

        [Fact]
        public void HappyPath_ReturnsBase64StdCborResult()
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor());

            var cborB64 = result["cbor"]?.Value<string>();
            Assert.NotNull(cborB64);

            // Must be base64-std (may contain +, /, or = padding — none of the url-safe chars).
            // More precisely: Convert.FromBase64String must succeed.
            var decoded = Convert.FromBase64String(cborB64!);
            Assert.True(decoded.Length > 0);
        }

        [Fact]
        public void HappyPath_PwEntryAddedToStore()
        {
            var handler = MakeHandler(out var store);
            CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor(rpId: "test.example"));

            var all = store.GetAll();
            Assert.Single(all);
            Assert.Equal("test.example", all[0].RpId);
            Assert.Equal("user@example.com", all[0].UserName);
            Assert.Equal(-7, all[0].AlgId);
        }

        [Fact]
        public void HappyPath_ResponseDecodesAsAttestationObject()
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor());

            var decoded = Convert.FromBase64String(result["cbor"]!.Value<string>()!);
            var reader = new CborReader(decoded);

            int count = reader.ReadMapHeader();
            Assert.Equal(3, count);

            string? fmt = null;
            byte[]? authData = null;
            bool hasEmptyAttStmt = false;

            // CTAP2 §6.1 integer keys: 1=fmt, 2=authData, 3=attStmt.
            // Natural bytewise-lex order for small uints is 1,2,3.
            for (int i = 0; i < count; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                switch (key)
                {
                    case 1: // fmt
                        fmt = reader.ReadTextString();
                        break;
                    case 2: // authData
                        authData = reader.ReadByteString();
                        break;
                    case 3: // attStmt
                        int stmtCount = reader.ReadMapHeader();
                        hasEmptyAttStmt = (stmtCount == 0);
                        break;
                    default:
                        reader.SkipValue();
                        break;
                }
            }

            Assert.Equal("none", fmt);
            Assert.NotNull(authData);
            Assert.True(hasEmptyAttStmt, "attStmt must be an empty map for fmt=none.");
            Assert.True(authData!.Length >= 55, "authData too short to contain RP ID hash + flags + AAGUID + credId.");
        }

        [Fact]
        public void HappyPath_UV_False_AuthDataFlagsNoUvBit()
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor(), uv: false);

            var authData = ExtractAuthDataFromResponse(result);
            byte flags = authData[32];

            // UP = 0x01 set, UV = 0x04 NOT set, AT = 0x40 set.
            Assert.True((flags & 0x01) != 0, "UP flag must be set.");
            Assert.True((flags & 0x04) == 0, "UV flag must NOT be set when uv=false.");
            Assert.True((flags & 0x40) != 0, "AT flag must be set.");

            // Full expected flags: 0x41 (UP | AT)
            Assert.Equal(0x41, flags);
        }

        [Fact]
        public void HappyPath_UV_True_AuthDataFlagsHasUvBit()
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor(), uv: true);

            var authData = ExtractAuthDataFromResponse(result);
            byte flags = authData[32];

            // UP = 0x01, UV = 0x04, AT = 0x40 → 0x45
            Assert.True((flags & 0x01) != 0, "UP flag must be set.");
            Assert.True((flags & 0x04) != 0, "UV flag must be set when uv=true.");
            Assert.True((flags & 0x40) != 0, "AT flag must be set.");

            Assert.Equal(0x45, flags);
        }

        [Fact]
        public void HappyPath_AuthDataStartsWithRpIdHash()
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor(rpId: "example.com"), uv: false);

            var authData = ExtractAuthDataFromResponse(result);
            var expectedHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("example.com"));
            Assert.Equal(expectedHash, authData[..32]);
        }

        [Fact]
        public void HappyPath_UvDefault_FalseWhenParamAbsent()
        {
            // Call without the 'uv' key in params.
            var handler = MakeHandler(out _);
            var result = handler.Handle("passkee.makeCredentialRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(BuildMinimalMakeCredentialCbor()),
            });

            var authData = ExtractAuthDataFromResponse((JObject)result!);
            byte flags = authData[32];
            Assert.True((flags & 0x04) == 0, "UV should default to false when param absent.");
        }

        // ── Error: unsupported algorithm ─────────────────────────────────────

        [Fact]
        public void MissingES256_ThrowsUnsupportedAlgorithm()
        {
            // Use COSE alg -257 (RS256) only — no ES256.
            var algEntry = MapOf(
                (T("type"), T("public-key")),
                (T("alg"),  N(-257)));

            var clientDataHash = new byte[32];
            var userId         = new byte[16];

            var rpMap = MapOf((T("id"), T("example.com")));
            var userMap = MapOf(
                (T("id"),   B(userId)),
                (T("name"), T("user")));
            var pubKeyCredParams = ArrayOf(algEntry);

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(1), B(clientDataHash)),
                (U(2), rpMap),
                (U(3), userMap),
                (U(4), pubKeyCredParams),
                (U(5), EmptyArray()),
            });
            var cborBytes = w.Encode();

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(cborBytes),
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.UnsupportedAlgorithm, ex.Code);
        }

        [Fact]
        public void EmptyPubKeyCredParams_ThrowsUnsupportedAlgorithm()
        {
            var clientDataHash = new byte[32];
            var userId         = new byte[16];

            var rpMap   = MapOf((T("id"), T("example.com")));
            var userMap = MapOf((T("id"), B(userId)), (T("name"), T("u")));

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (U(1), B(clientDataHash)),
                (U(2), rpMap),
                (U(3), userMap),
                (U(4), EmptyArray()),   // no algorithms
                (U(5), EmptyArray()),
            });

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(w.Encode()),
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.UnsupportedAlgorithm, ex.Code);
        }

        // ── Error: credential excluded ───────────────────────────────────────

        [Fact]
        public void ExcludeList_Hit_ThrowsCredentialExcluded()
        {
            var handler = MakeHandler(out var store);

            // Create a credential in the store whose raw ID we know.
            var rawCredId = new byte[32];
            rawCredId[0] = 0xAB;
            var credentialId = Base64Url.Encode(rawCredId);
            store.Add(new PasskeyRecord
            {
                CredentialId = credentialId,
                RpId = "example.com",
                UserName = "u",
                UserHandle = "uh",
            });

            // Build a request that excludes this credential.
            var cbor = BuildMinimalMakeCredentialCbor(
                rpId: "example.com",
                excludeList: new[] { rawCredId });

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(cbor),
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.CredentialExcluded, ex.Code);
        }

        [Fact]
        public void ExcludeList_NoHit_Succeeds()
        {
            var handler = MakeHandler(out var store);

            // Store a different credential.
            store.Add(new PasskeyRecord
            {
                CredentialId = "other-cred",
                RpId = "example.com",
                UserName = "u",
                UserHandle = "uh",
            });

            // excludeList contains a non-matching ID.
            var unrelatedId = new byte[32];
            unrelatedId[0] = 0xFF;

            var cbor = BuildMinimalMakeCredentialCbor(
                rpId: "example.com",
                excludeList: new[] { unrelatedId });

            // Should succeed — no credential with this ID in store.
            var result = handler.Handle("passkee.makeCredentialRaw", new JObject
            {
                ["cbor"] = Convert.ToBase64String(cbor),
                ["uv"]   = false,
            });
            Assert.NotNull(result);
        }

        // ── Error: malformed CBOR ────────────────────────────────────────────

        [Fact]
        public void MalformedCbor_Truncated_ThrowsInvalidParams()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0xA5 }), // map says 5 items, none follow
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void MalformedCbor_NotBase64_ThrowsInvalidParams()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = "!!!not-base64!!!",
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void MalformedCbor_IndefiniteLengthMap_ThrowsInvalidParams()
        {
            // 0xBF = indefinite-length map start — CTAP2 forbids this.
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0xBF }),
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        // ── Error: missing required field ────────────────────────────────────

        [Fact]
        public void MissingClientDataHash_ThrowsInvalidParams()
        {
            var userId = new byte[16];
            var rpMap   = MapOf((T("id"), T("example.com")));
            var userMap = MapOf((T("id"), B(userId)), (T("name"), T("u")));
            var algEntry = MapOf((T("type"), T("public-key")), (T("alg"), N(-7)));

            var w = new CborWriter();
            // key 1 is absent — only rp (2), user (3), pubKeyCredParams (4), excludeList (5).
            w.WriteMap(new[]
            {
                (U(2), rpMap),
                (U(3), userMap),
                (U(4), ArrayOf(algEntry)),
                (U(5), EmptyArray()),
            });

            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(w.Encode()),
                    ["uv"]   = false,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void MissingCborParam_ThrowsInvalidParams()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    // "cbor" key absent
                    ["uv"] = false,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        [Fact]
        public void NullParams_ThrowsInvalidParams()
        {
            var handler = MakeHandler(out _);
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", null));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        // ── UV flag propagation: additional verification ──────────────────────

        [Theory]
        [InlineData(true,  0x45)] // UP | UV | AT
        [InlineData(false, 0x41)] // UP | AT
        public void UvFlag_ProducesCorrectFlags(bool uv, byte expectedFlags)
        {
            var handler = MakeHandler(out _);
            var result = CallMakeCredentialRaw(handler, BuildMinimalMakeCredentialCbor(), uv: uv);

            var authData = ExtractAuthDataFromResponse(result);
            Assert.Equal(expectedFlags, authData[32]);
        }

        // ── Dispatch: unknown method still throws ─────────────────────────────

        [Fact]
        public void DispatchTable_MakeCredentialRaw_IsRouted()
        {
            // Verify the method name is wired in via Handle() dispatch.
            var handler = MakeHandler(out _);
            // Using an invalid-but-recognisable cbor to confirm routing, not CBOR parsing.
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("passkee.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0x00 }), // uint 0, not a map
                    ["uv"]   = false,
                }));
            // Should get InvalidParams (from malformed CBOR), NOT MethodNotFound.
            Assert.NotEqual(RpcErrorCode.MethodNotFound, ex.Code);
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static byte[] ExtractAuthDataFromResponse(JObject result)
        {
            var cborB64 = result["cbor"]!.Value<string>()!;
            var decoded = Convert.FromBase64String(cborB64);

            var reader = new CborReader(decoded);
            int count = reader.ReadMapHeader();

            // CTAP2 §6.1: key 2 = authData (byte string).
            for (int i = 0; i < count; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                if (key == 2)
                    return reader.ReadByteString();
                reader.SkipValue();
            }

            throw new InvalidOperationException("authData (key 2) not found in attestation object.");
        }

        // Helper extension for array concatenation.
        private static byte[] ArrayOf(IEnumerable<byte[]> items) => ArrayOf(new List<byte[]>(items).ToArray());
    }
}
