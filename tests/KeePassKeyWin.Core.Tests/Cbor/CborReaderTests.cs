using System;
using System.Collections.Generic;
using System.Text;
using KeePassKeyWin.Core.Cbor;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Cbor
{
    public class CborReaderTests
    {
        // ── Encode helpers (CborWriter round-trip source) ────────────────────

        private static byte[] Uint(ulong v)   { var w = new CborWriter(); w.WriteUnsignedInt(v); return w.Encode(); }
        private static byte[] Neg(long v)     { var w = new CborWriter(); w.WriteNegativeInt(v); return w.Encode(); }
        private static byte[] Bstr(byte[] b)  { var w = new CborWriter(); w.WriteByteString(b);  return w.Encode(); }
        private static byte[] Tstr(string s)  { var w = new CborWriter(); w.WriteTextString(s);  return w.Encode(); }
        private static byte[] ArrHdr(int n)   { var w = new CborWriter(); w.WriteArrayHeader(n); return w.Encode(); }

        private static byte[] Concat(params byte[][] parts)
        {
            int total = 0;
            foreach (var p in parts) total += p.Length;
            var result = new byte[total];
            int offset = 0;
            foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
            return result;
        }

        // ── unsigned integer (major type 0) ─────────────────────────────────

        [Theory]
        [InlineData(0UL)]
        [InlineData(1UL)]
        [InlineData(23UL)]
        [InlineData(24UL)]
        [InlineData(255UL)]
        [InlineData(256UL)]
        [InlineData(65535UL)]
        [InlineData(65536UL)]
        [InlineData(ulong.MaxValue)]
        public void ReadUnsignedInt_RoundTrip(ulong value)
        {
            var encoded = Uint(value);
            var reader = new CborReader(encoded);
            Assert.Equal(value, reader.ReadUnsignedInt());
            Assert.True(reader.IsAtEnd);
        }

        [Fact]
        public void ReadUnsignedInt_WrongType_Throws()
        {
            // Negative integer (major type 1) when unsigned expected.
            var reader = new CborReader(Neg(-1));
            Assert.Throws<CborReaderException>(() => reader.ReadUnsignedInt());
        }

        // ── negative integer (major type 1) ─────────────────────────────────

        [Theory]
        [InlineData(-1L)]
        [InlineData(-7L)]   // ES256 COSE alg
        [InlineData(-24L)]
        [InlineData(-25L)]
        [InlineData(-256L)]
        [InlineData(-257L)]
        public void ReadNegativeInt_RoundTrip(long value)
        {
            var encoded = Neg(value);
            var reader = new CborReader(encoded);
            Assert.Equal(value, reader.ReadNegativeInt());
            Assert.True(reader.IsAtEnd);
        }

        [Fact]
        public void ReadNegativeInt_WrongType_Throws()
        {
            var reader = new CborReader(Uint(5));
            Assert.Throws<CborReaderException>(() => reader.ReadNegativeInt());
        }

        // ── byte string (major type 2) ───────────────────────────────────────

        [Fact]
        public void ReadByteString_Empty()
        {
            var reader = new CborReader(Bstr(Array.Empty<byte>()));
            Assert.Equal(Array.Empty<byte>(), reader.ReadByteString());
            Assert.True(reader.IsAtEnd);
        }

        [Fact]
        public void ReadByteString_32Bytes_RoundTrip()
        {
            var data = new byte[32];
            new Random(42).NextBytes(data);
            var reader = new CborReader(Bstr(data));
            Assert.Equal(data, reader.ReadByteString());
        }

        [Fact]
        public void ReadByteString_WrongType_Throws()
        {
            var reader = new CborReader(Tstr("hello"));
            Assert.Throws<CborReaderException>(() => reader.ReadByteString());
        }

        // ── text string (major type 3) ───────────────────────────────────────

        [Fact]
        public void ReadTextString_Ascii_RoundTrip()
        {
            var reader = new CborReader(Tstr("example.com"));
            Assert.Equal("example.com", reader.ReadTextString());
        }

        [Fact]
        public void ReadTextString_Utf8_RoundTrip()
        {
            const string text = "Héllo wörld";
            var reader = new CborReader(Tstr(text));
            Assert.Equal(text, reader.ReadTextString());
        }

        [Fact]
        public void ReadTextString_WrongType_Throws()
        {
            var reader = new CborReader(Bstr(new byte[] { 0x01 }));
            Assert.Throws<CborReaderException>(() => reader.ReadTextString());
        }

        // ── array header (major type 4) ──────────────────────────────────────

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(24)]
        public void ReadArrayHeader_RoundTrip(int count)
        {
            var reader = new CborReader(ArrHdr(count));
            Assert.Equal(count, reader.ReadArrayHeader());
        }

        [Fact]
        public void ReadArrayHeader_WrongType_Throws()
        {
            var reader = new CborReader(Uint(3));
            Assert.Throws<CborReaderException>(() => reader.ReadArrayHeader());
        }

        // ── map header (major type 5) ────────────────────────────────────────

        [Fact]
        public void ReadMapHeader_Zero()
        {
            var w = new CborWriter();
            w.WriteMap(Array.Empty<(byte[], byte[])>());
            var reader = new CborReader(w.Encode());
            Assert.Equal(0, reader.ReadMapHeader());
        }

        [Fact]
        public void ReadMapHeader_WrongType_Throws()
        {
            var reader = new CborReader(ArrHdr(3));
            Assert.Throws<CborReaderException>(() => reader.ReadMapHeader());
        }

        // ── PeekMajorType ────────────────────────────────────────────────────

        [Fact]
        public void PeekMajorType_DoesNotAdvancePosition()
        {
            var reader = new CborReader(Uint(42));
            Assert.Equal(0, reader.PeekMajorType()); // MT0
            Assert.Equal(0, reader.PeekMajorType()); // same again — position unchanged
            Assert.Equal(0, reader.Position);
        }

        [Fact]
        public void PeekMajorType_ReturnsCorrectType()
        {
            Assert.Equal(0, new CborReader(Uint(1)).PeekMajorType());
            Assert.Equal(1, new CborReader(Neg(-1)).PeekMajorType());
            Assert.Equal(2, new CborReader(Bstr(new byte[0])).PeekMajorType());
            Assert.Equal(3, new CborReader(Tstr("x")).PeekMajorType());
            Assert.Equal(4, new CborReader(ArrHdr(0)).PeekMajorType());
        }

        // ── SkipValue ────────────────────────────────────────────────────────

        [Fact]
        public void SkipValue_SkipsUnsignedInt()
        {
            var data = Concat(Uint(99), Uint(42));
            var reader = new CborReader(data);
            reader.SkipValue();
            Assert.Equal(42UL, reader.ReadUnsignedInt());
        }

        [Fact]
        public void SkipValue_SkipsByteString()
        {
            var data = Concat(Bstr(new byte[] { 0xAA, 0xBB }), Uint(7));
            var reader = new CborReader(data);
            reader.SkipValue();
            Assert.Equal(7UL, reader.ReadUnsignedInt());
        }

        [Fact]
        public void SkipValue_SkipsNestedMap()
        {
            // Build: {1: {-1: "x"}} followed by uint 99
            var inner = new CborWriter();
            inner.WriteMap(new[] { (Neg(-1), Tstr("x")) });

            var outer = new CborWriter();
            outer.WriteMap(new[] { (Uint(1), inner.Encode()) });

            var data = Concat(outer.Encode(), Uint(99));
            var reader = new CborReader(data);
            reader.SkipValue(); // skip the outer map
            Assert.Equal(99UL, reader.ReadUnsignedInt());
        }

        // ── IsAtEnd / Position ───────────────────────────────────────────────

        [Fact]
        public void IsAtEnd_TrueAfterReadingAllBytes()
        {
            var reader = new CborReader(Uint(0));
            Assert.False(reader.IsAtEnd);
            reader.ReadUnsignedInt();
            Assert.True(reader.IsAtEnd);
        }

        [Fact]
        public void Position_AdvancesCorrectly()
        {
            var data = Concat(Uint(1), Uint(2), Uint(3));
            var reader = new CborReader(data);
            Assert.Equal(0, reader.Position);
            reader.ReadUnsignedInt();
            Assert.Equal(1, reader.Position);
            reader.ReadUnsignedInt();
            Assert.Equal(2, reader.Position);
        }

        // ── Malformed input ──────────────────────────────────────────────────

        [Fact]
        public void Truncated_Throws()
        {
            // 0x58 = major type 2, additional-info 24 (1-byte length follows), then nothing
            var reader = new CborReader(new byte[] { 0x58 });
            Assert.Throws<CborReaderException>(() => reader.ReadByteString());
        }

        [Fact]
        public void TruncatedContent_Throws()
        {
            // 0x42 = 2-byte bstr, but only 1 byte of content follows
            var reader = new CborReader(new byte[] { 0x42, 0xAA });
            Assert.Throws<CborReaderException>(() => reader.ReadByteString());
        }

        [Fact]
        public void EmptyBuffer_PeekThrows()
        {
            var reader = new CborReader(Array.Empty<byte>());
            Assert.Throws<CborReaderException>(() => reader.PeekMajorType());
        }

        [Fact]
        public void IndefiniteLengthByteString_Throws()
        {
            // 0x5F = major type 2, additional-info 31 (indefinite)
            var reader = new CborReader(new byte[] { 0x5F });
            Assert.Throws<CborReaderException>(() => reader.ReadByteString());
        }

        [Fact]
        public void IndefiniteLengthArray_Throws()
        {
            // 0x9F = major type 4, additional-info 31 (indefinite)
            var reader = new CborReader(new byte[] { 0x9F });
            Assert.Throws<CborReaderException>(() => reader.ReadArrayHeader());
        }

        [Fact]
        public void IndefiniteLengthMap_Throws()
        {
            // 0xBF = major type 5, additional-info 31 (indefinite)
            var reader = new CborReader(new byte[] { 0xBF });
            Assert.Throws<CborReaderException>(() => reader.ReadMapHeader());
        }

        [Fact]
        public void IndefiniteLengthUnsignedInt_Throws()
        {
            // 0x1F = major type 0, additional-info 31
            var reader = new CborReader(new byte[] { 0x1F });
            Assert.Throws<CborReaderException>(() => reader.ReadUnsignedInt());
        }

        [Fact]
        public void ReservedAdditionalInfo28_Throws()
        {
            // 0x1C = major type 0, additional-info 28 (reserved)
            var reader = new CborReader(new byte[] { 0x1C });
            Assert.Throws<CborReaderException>(() => reader.ReadUnsignedInt());
        }

        [Fact]
        public void TagMajorType6_Throws()
        {
            // 0xC0 = major type 6, tag 0
            var reader = new CborReader(new byte[] { 0xC0, 0x00 });
            Assert.Throws<CborReaderException>(() => reader.SkipValue());
        }

        [Theory]
        [InlineData(0xF4)] // false
        [InlineData(0xF5)] // true
        [InlineData(0xF6)] // null
        [InlineData(0xF7)] // undefined
        public void SkipValue_SimpleValues_AreSkipped(byte b)
        {
            // CTAP2 §6.1.1 options map uses false/true; tolerated by SkipValue
            // so `options` can be ignored without parsing booleans.
            var reader = new CborReader(new byte[] { b });
            reader.SkipValue();
            Assert.True(reader.IsAtEnd);
        }

        [Theory]
        [InlineData(new byte[] { 0xF8, 0x20 })]               // MT7 AI 24 (1-byte simple value ext)
        [InlineData(new byte[] { 0xF9, 0x00, 0x00 })]         // MT7 AI 25 (half float)
        [InlineData(new byte[] { 0xFA, 0x00, 0x00, 0x00, 0x00 })] // MT7 AI 26 (single float)
        public void SkipValue_MT7FloatsAndExt_Throw(byte[] bytes)
        {
            var reader = new CborReader(bytes);
            Assert.Throws<CborReaderException>(() => reader.SkipValue());
        }

        [Fact]
        public void SkipValue_OptionsMapWithBools_IsSkipped()
        {
            // Regression for Session 6 Phase 3 failure: webauthn.io sends
            // options as `{rk: true, uv: true}` (CBOR a2 62726b f5 627576 f5).
            // SkipValue must tolerate it so we can ignore key 7.
            var bytes = new byte[] { 0xa2, 0x62, 0x72, 0x6b, 0xf5, 0x62, 0x75, 0x76, 0xf5 };
            var reader = new CborReader(bytes);
            reader.SkipValue();
            Assert.True(reader.IsAtEnd);
        }

        // ── ReadBool (for CTAP2 §6.2 options map) ─────────────────────────────

        [Fact]
        public void ReadBool_True_Returns_0xF5()
        {
            var reader = new CborReader(new byte[] { 0xF5 });
            Assert.True(reader.ReadBool());
            Assert.True(reader.IsAtEnd);
        }

        [Fact]
        public void ReadBool_False_Returns_0xF4()
        {
            var reader = new CborReader(new byte[] { 0xF4 });
            Assert.False(reader.ReadBool());
            Assert.True(reader.IsAtEnd);
        }

        [Theory]
        [InlineData(0x00)] // uint 0 (MT0)
        [InlineData(0xF6)] // null — simple value but not a bool
        [InlineData(0xF7)] // undefined — simple value but not a bool
        [InlineData(0x01)] // uint 1
        public void ReadBool_NonBool_Throws(byte b)
        {
            var reader = new CborReader(new byte[] { b });
            Assert.Throws<CborReaderException>(() => reader.ReadBool());
        }

        [Fact]
        public void ReadBool_EmptyBuffer_Throws()
        {
            var reader = new CborReader(Array.Empty<byte>());
            Assert.Throws<CborReaderException>(() => reader.ReadBool());
        }

        [Fact]
        public void LengthBomb_ByteStringClaiming2Gb_Throws()
        {
            // Major type 2 (byte string), additional-info 26 (4-byte length), then 0x80000000 = 2^31.
            // The buffer has only 6 bytes total so this must fail without allocating 2 GB.
            var reader = new CborReader(new byte[] { 0x5A, 0x80, 0x00, 0x00, 0x00 });
            var ex = Assert.Throws<CborReaderException>(() => reader.ReadByteString());
            Assert.Contains("remain", ex.Message);
        }

        [Fact]
        public void LengthBomb_ByteStringClaimingInt32MaxPlus1_Throws()
        {
            // 8-byte length = 2^32 (exceeds Int32.MaxValue).
            // 0x5B = major type 2, additional-info 27 (8-byte uint length).
            var header = new byte[] { 0x5B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
            var reader = new CborReader(header);
            Assert.Throws<CborReaderException>(() => reader.ReadByteString());
        }

        // ── Synthetic CTAP2 MakeCredential request vector ────────────────────
        //
        // Builds a minimal but structurally complete authenticatorMakeCredential input
        // (CTAP 2.1 §6.1.1) using CborWriter, then verifies CborReader can parse
        // all 9 top-level map keys including the ones we skip (6-9).

        [Fact]
        public void Ctap2MakeCredential_SyntheticVector_ParsesAllKeys()
        {
            // clientDataHash (key 1): 32 zero bytes
            var clientDataHash = new byte[32];

            // rp map (key 2): {id: "example.com", name: "Example"}
            var rpMap = new CborWriter();
            rpMap.WriteMap(new[]
            {
                (Tstr("id"),   Tstr("example.com")),
                (Tstr("name"), Tstr("Example")),
            });

            // user map (key 3): {id: <16 bytes>, name: "user@example.com", displayName: "User"}
            var userId = new byte[16];
            var userMap = new CborWriter();
            userMap.WriteMap(new[]
            {
                (Tstr("id"),          Bstr(userId)),
                (Tstr("name"),        Tstr("user@example.com")),
                (Tstr("displayName"), Tstr("User")),
            });

            // pubKeyCredParams (key 4): [{type: "public-key", alg: -7}]
            var algEntry = new CborWriter();
            algEntry.WriteMap(new[]
            {
                (Tstr("type"), Tstr("public-key")),
                (Tstr("alg"),  Neg(-7)),
            });
            var pkParams = new CborWriter();
            pkParams.WriteArrayHeader(1);
            // WriteMap result is already encoded; write the raw bytes inline.
            // For the array element we'll use a helper that splices the raw bytes.
            // Instead, encode the param map separately and concatenate.
            var algEntryBytes = algEntry.Encode();

            // excludeList (key 5): [] (empty)
            var excludeList = new CborWriter();
            excludeList.WriteArrayHeader(0);

            // extensions (key 6): {} empty map
            var extensions = new CborWriter();
            extensions.WriteMap(Array.Empty<(byte[], byte[])>());

            // options (key 7): {rk: true}
            // true = major type 7, additional-info 21 = 0xF5
            var trueBytes = new byte[] { 0xF5 }; // We don't use CborWriter for this (it's MT7)
            // We need to pass options as a raw CBOR value. Since CborWriter doesn't encode bool,
            // we build the map by hand for this test: skip key 7 entirely (it's optional).
            // Alternatively, encode options as an empty map since we're just testing parse-and-skip.
            var options = new CborWriter();
            options.WriteMap(Array.Empty<(byte[], byte[])>());

            // Build outer map with keys 1-7 (skip 8/9 as optional).
            // We must provide raw value bytes for each, so we encode each separately.
            var w = new CborWriter();
            var pkParamsRaw = BuildArray(new[] { algEntryBytes });

            w.WriteMap(new[]
            {
                (Uint(1), Bstr(clientDataHash)),
                (Uint(2), rpMap.Encode()),
                (Uint(3), userMap.Encode()),
                (Uint(4), pkParamsRaw),
                (Uint(5), excludeList.Encode()),
                (Uint(6), extensions.Encode()),
                (Uint(7), options.Encode()),
            });

            var encoded = w.Encode();
            var reader = new CborReader(encoded);

            int mapCount = reader.ReadMapHeader();
            Assert.Equal(7, mapCount);

            var seen = new HashSet<ulong>();
            for (int i = 0; i < mapCount; i++)
            {
                ulong key = reader.ReadUnsignedInt();
                seen.Add(key);

                switch (key)
                {
                    case 1: // clientDataHash
                        var cdh = reader.ReadByteString();
                        Assert.Equal(32, cdh.Length);
                        break;

                    case 2: // rp map
                    {
                        int rpCount = reader.ReadMapHeader();
                        string? rpId = null, rpName = null;
                        for (int k = 0; k < rpCount; k++)
                        {
                            string field = reader.ReadTextString();
                            string val   = reader.ReadTextString();
                            if (field == "id")   rpId   = val;
                            if (field == "name") rpName = val;
                        }
                        Assert.Equal("example.com", rpId);
                        Assert.Equal("Example", rpName);
                        break;
                    }

                    case 3: // user map
                    {
                        int userCount = reader.ReadMapHeader();
                        string? uName = null, uDispName = null;
                        byte[]? uId = null;
                        for (int k = 0; k < userCount; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "id")
                                uId = reader.ReadByteString();
                            else
                            {
                                string val = reader.ReadTextString();
                                if (field == "name")        uName     = val;
                                if (field == "displayName") uDispName = val;
                            }
                        }
                        Assert.Equal("user@example.com", uName);
                        Assert.Equal("User", uDispName);
                        Assert.NotNull(uId);
                        Assert.Equal(16, uId!.Length);
                        break;
                    }

                    case 4: // pubKeyCredParams
                    {
                        int arrCount = reader.ReadArrayHeader();
                        Assert.Equal(1, arrCount);
                        int paramCount = reader.ReadMapHeader();
                        string? algType = null;
                        long algId = 0;
                        for (int k = 0; k < paramCount; k++)
                        {
                            string field = reader.ReadTextString();
                            if (field == "alg")
                                algId = reader.ReadNegativeInt();
                            else
                                algType = reader.ReadTextString();
                        }
                        Assert.Equal("public-key", algType);
                        Assert.Equal(-7L, algId);
                        break;
                    }

                    case 5: // excludeList (empty array)
                    {
                        int exCount = reader.ReadArrayHeader();
                        Assert.Equal(0, exCount);
                        break;
                    }

                    default: // keys 6, 7 — skip
                        reader.SkipValue();
                        break;
                }
            }

            Assert.Contains(1UL, seen);
            Assert.Contains(2UL, seen);
            Assert.Contains(3UL, seen);
            Assert.Contains(4UL, seen);
            Assert.Contains(5UL, seen);
            Assert.True(reader.IsAtEnd);
        }

        // Helper: builds a definite-length CBOR array from pre-encoded item bytes.
        private static byte[] BuildArray(byte[][] items)
        {
            var w = new CborWriter();
            w.WriteArrayHeader(items.Length);
            var encoded = w.Encode();
            // Concatenate array header + each raw item.
            int total = encoded.Length;
            foreach (var item in items) total += item.Length;
            var result = new byte[total];
            Array.Copy(encoded, 0, result, 0, encoded.Length);
            int offset = encoded.Length;
            foreach (var item in items)
            {
                Array.Copy(item, 0, result, offset, item.Length);
                offset += item.Length;
            }
            return result;
        }
    }
}
