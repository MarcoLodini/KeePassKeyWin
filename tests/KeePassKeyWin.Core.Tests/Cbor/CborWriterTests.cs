using System;
using System.Collections.Generic;
using KeePassKeyWin.Core.Cbor;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Cbor
{
    public class CborWriterTests
    {
        // Encoding helpers.
        private static byte[] Uint(ulong v) { var w = new CborWriter(); w.WriteUnsignedInt(v); return w.Encode(); }
        private static byte[] Neg(long v)   { var w = new CborWriter(); w.WriteNegativeInt(v); return w.Encode(); }
        private static byte[] Bstr(byte[] b){ var w = new CborWriter(); w.WriteByteString(b);   return w.Encode(); }
        private static byte[] Tstr(string s){ var w = new CborWriter(); w.WriteTextString(s);   return w.Encode(); }

        // --- unsigned integer (major type 0) ---

        [Theory]
        [InlineData(0,   new byte[] { 0x00 })]
        [InlineData(1,   new byte[] { 0x01 })]
        [InlineData(23,  new byte[] { 0x17 })]
        [InlineData(24,  new byte[] { 0x18, 0x18 })]
        [InlineData(255, new byte[] { 0x18, 0xff })]
        [InlineData(256, new byte[] { 0x19, 0x01, 0x00 })]
        [InlineData(65535, new byte[] { 0x19, 0xff, 0xff })]
        [InlineData(65536, new byte[] { 0x1a, 0x00, 0x01, 0x00, 0x00 })]
        public void WriteUnsignedInt_KnownVectors(ulong value, byte[] expected)
        {
            Assert.Equal(expected, Uint(value));
        }

        // --- negative integer (major type 1) ---

        [Theory]
        [InlineData(-1,   new byte[] { 0x20 })]          // -1  → MT1 value 0
        [InlineData(-7,   new byte[] { 0x26 })]          // -7  → MT1 value 6 (ES256 alg)
        [InlineData(-24,  new byte[] { 0x37 })]          // -24 → MT1 value 23
        [InlineData(-25,  new byte[] { 0x38, 0x18 })]    // -25 → MT1 value 24, 1-byte ext
        public void WriteNegativeInt_KnownVectors(long value, byte[] expected)
        {
            Assert.Equal(expected, Neg(value));
        }

        [Fact]
        public void WriteNegativeInt_PositiveValue_Throws()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Neg(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => Neg(1));
        }

        // --- byte string (major type 2) ---

        [Fact]
        public void WriteByteString_Empty()
        {
            Assert.Equal(new byte[] { 0x40 }, Bstr(Array.Empty<byte>()));
        }

        [Fact]
        public void WriteByteString_ShortData()
        {
            var data = new byte[] { 0xDE, 0xAD };
            var expected = new byte[] { 0x42, 0xDE, 0xAD };
            Assert.Equal(expected, Bstr(data));
        }

        [Fact]
        public void WriteByteString_32Bytes()
        {
            var data = new byte[32];
            var result = Bstr(data);
            // 0x58 0x20 followed by 32 zeros
            Assert.Equal(0x58, result[0]);
            Assert.Equal(0x20, result[1]);
            Assert.Equal(34, result.Length);
        }

        // --- text string (major type 3) ---

        [Fact]
        public void WriteTextString_Ascii()
        {
            // "abc" → 0x63 0x61 0x62 0x63
            Assert.Equal(new byte[] { 0x63, 0x61, 0x62, 0x63 }, Tstr("abc"));
        }

        // --- map sorting ---

        [Fact]
        public void WriteMap_SortsKeysByBytewiseLex()
        {
            // Keys: uint 3 (0x03), uint 1 (0x01), uint 2 (0x02)
            // Expected sort order: 0x01, 0x02, 0x03
            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (Uint(3), Uint(30)),
                (Uint(1), Uint(10)),
                (Uint(2), Uint(20)),
            });
            var encoded = w.Encode();

            // Map header: 0xa3 (3 items)
            Assert.Equal(0xa3, encoded[0]);
            // First key should be 0x01, second 0x02, third 0x03
            Assert.Equal(0x01, encoded[1]);
            Assert.Equal(0x0a, encoded[2]); // value 10
            Assert.Equal(0x02, encoded[3]);
            Assert.Equal(0x14, encoded[4]); // value 20
            Assert.Equal(0x03, encoded[5]);
            // Uint(30) = 0x18 0x1e (30 > 23, requires 1-byte extra).
            Assert.Equal(0x18, encoded[6]);
            Assert.Equal(0x1e, encoded[7]); // value 30
        }

        [Fact]
        public void WriteMap_NegativeKeysSortCorrectly()
        {
            // -1 encodes as 0x20, -2 as 0x21, -3 as 0x22
            // Bytewise lex: 0x20 < 0x21 < 0x22 → order -1, -2, -3
            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (Neg(-3), Uint(3)),
                (Neg(-1), Uint(1)),
                (Neg(-2), Uint(2)),
            });
            var encoded = w.Encode();

            // Sorted layout: [0xa3][0x20][0x01][0x21][0x02][0x22][0x03]
            Assert.Equal(0xa3, encoded[0]);
            Assert.Equal(0x20, encoded[1]); // key -1 → 0x20
            Assert.Equal(0x01, encoded[2]); // value 1
            Assert.Equal(0x21, encoded[3]); // key -2 → 0x21
            Assert.Equal(0x02, encoded[4]); // value 2
            Assert.Equal(0x22, encoded[5]); // key -3 → 0x22
            Assert.Equal(0x03, encoded[6]); // value 3
            // Keys at positions 1, 3, 5 must be strictly increasing.
            Assert.True(encoded[1] < encoded[3]);
            Assert.True(encoded[3] < encoded[5]);
        }

        [Fact]
        public void WriteMap_EmptyMap()
        {
            var w = new CborWriter();
            w.WriteMap(Array.Empty<(byte[], byte[])>());
            Assert.Equal(new byte[] { 0xa0 }, w.Encode());
        }
    }
}
