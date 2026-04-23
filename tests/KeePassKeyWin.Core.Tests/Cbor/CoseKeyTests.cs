using System;
using System.Security.Cryptography;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Cbor
{
    public class CoseKeyTests
    {
        // ── RS256 (EncodeRsa) tests ───────────────────────────────────────────

        [Fact]
        public void EncodeRsa_ValidParameters_ProducesNonEmptyBytes()
        {
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var cbor = CoseKey.EncodeRsa(n, e);
            Assert.NotNull(cbor);
            Assert.True(cbor.Length > 0);
        }

        [Fact]
        public void EncodeRsa_StartsWithMapHeader4()
        {
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var cbor = CoseKey.EncodeRsa(n, e);
            // CBOR map with 4 items: 0xa4
            Assert.Equal(0xa4, cbor[0]);
        }

        [Fact]
        public void EncodeRsa_ContainsRs256AlgValue()
        {
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var cbor = CoseKey.EncodeRsa(n, e);

            // alg = -257 encodes as 0x39 0x01 0x00 in CBOR (major type 1, value 256 = -1-256 = -257).
            // The alg label is 3 (0x03); the value follows.
            // Search for 0x03 followed by 0x39 0x01 0x00.
            bool found = false;
            for (int i = 0; i < cbor.Length - 3; i++)
            {
                if (cbor[i] == 0x03 && cbor[i + 1] == 0x39 && cbor[i + 2] == 0x01 && cbor[i + 3] == 0x00)
                {
                    found = true;
                    break;
                }
            }
            Assert.True(found, "Expected alg key 0x03 followed by RS256 value (-257 = 0x39 0x01 0x00).");
        }

        [Fact]
        public void EncodeRsa_ContainsModulusBytes()
        {
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var cbor = CoseKey.EncodeRsa(n, e);
            // The modulus (256 bytes) should appear verbatim in the CBOR.
            Assert.True(ContainsSubarray(cbor, n), "Modulus bytes not found in COSE_Key CBOR.");
        }

        [Fact]
        public void EncodeRsa_MapKeysAreSorted()
        {
            // CTAP2 canonical sort for RS256 labels {1, 3, -1, -2}:
            // 1 → 0x01, 3 → 0x03, -1 → 0x20, -2 → 0x21
            // Sorted order: 0x01 < 0x03 < 0x20 < 0x21
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var cbor = CoseKey.EncodeRsa(n, e);

            int pos = 1; // skip map header (0xa4)
            byte prevKey = 0;
            for (int i = 0; i < 4; i++)
            {
                byte keyByte = cbor[pos];
                Assert.True(keyByte >= prevKey,
                    $"Key at index {i} (0x{keyByte:X2}) is not >= previous (0x{prevKey:X2}).");
                prevKey = keyByte;

                // Skip key byte (1 byte for small ints/negs).
                pos++;
                if (i < 2)
                {
                    // kty and alg values: kty=3 (1 byte 0x03), alg=-257 (3 bytes 0x39 0x01 0x00).
                    if (cbor[pos] <= 0x17)
                        pos += 1;       // 1-byte uint
                    else if (cbor[pos] == 0x39)
                        pos += 3;       // 3-byte negint (major type 1, ai=25)
                    else
                        pos += 1;
                }
                else
                {
                    // n and e values are bstrs: 0x59 for 2-byte length prefix (n=256 bytes), or 0x43 for e=3 bytes.
                    if (cbor[pos] == 0x59)
                    {
                        int len = (cbor[pos + 1] << 8) | cbor[pos + 2];
                        pos += 3 + len;
                    }
                    else if (cbor[pos] == 0x58)
                    {
                        int len = cbor[pos + 1];
                        pos += 2 + len;
                    }
                    else
                    {
                        // Short bstr (0x40..0x57): length = low 5 bits.
                        int len = cbor[pos] & 0x1F;
                        pos += 1 + len;
                    }
                }
            }
        }

        [Fact]
        public void EncodeRsa_EmptyModulus_Throws()
        {
            Assert.Throws<ArgumentException>(() => CoseKey.EncodeRsa(Array.Empty<byte>(), new byte[] { 0x01, 0x00, 0x01 }));
        }

        [Fact]
        public void EncodeRsa_EmptyExponent_Throws()
        {
            Assert.Throws<ArgumentException>(() => CoseKey.EncodeRsa(new byte[256], Array.Empty<byte>()));
        }


        [Fact]
        public void Encode_ValidCoordinates_ProducesNonEmptyBytes()
        {
            var x = new byte[32]; x[0] = 0x01;
            var y = new byte[32]; y[0] = 0x02;
            var cbor = CoseKey.Encode(x, y);
            Assert.NotNull(cbor);
            Assert.True(cbor.Length > 0);
        }

        [Fact]
        public void Encode_XNot32Bytes_Throws()
        {
            Assert.Throws<ArgumentException>(() => CoseKey.Encode(new byte[31], new byte[32]));
        }

        [Fact]
        public void Encode_YNot32Bytes_Throws()
        {
            Assert.Throws<ArgumentException>(() => CoseKey.Encode(new byte[32], new byte[33]));
        }

        [Fact]
        public void Encode_StartsWithMapHeader5()
        {
            var x = new byte[32];
            var y = new byte[32];
            var cbor = CoseKey.Encode(x, y);
            // CBOR map with 5 items: 0xa5
            Assert.Equal(0xa5, cbor[0]);
        }

        [Fact]
        public void Encode_ContainsEs256AlgValue()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var cbor = CoseKey.Encode(x, y);

            // alg = -7 encodes as 0x26 in CBOR.
            // The map is sorted; alg key (uint 3 = 0x03) should appear and be followed by 0x26.
            bool found = false;
            for (int i = 0; i < cbor.Length - 1; i++)
            {
                if (cbor[i] == 0x03 && cbor[i + 1] == 0x26)
                {
                    found = true;
                    break;
                }
            }
            Assert.True(found, "Expected alg key 0x03 followed by value -7 (0x26).");
        }

        [Fact]
        public void Encode_ContainsXAndYCoordinates()
        {
            var x = new byte[32]; for (int i = 0; i < 32; i++) x[i] = (byte)(i + 1);
            var y = new byte[32]; for (int i = 0; i < 32; i++) y[i] = (byte)(i + 0x40);
            var cbor = CoseKey.Encode(x, y);

            // x and y are 32-byte bstrs; encoded as 0x58 0x20 <bytes>.
            // Check that the x bytes appear in the CBOR.
            bool xFound = ContainsSubarray(cbor, x);
            bool yFound = ContainsSubarray(cbor, y);
            Assert.True(xFound, "X coordinate bytes not found in COSE_Key CBOR.");
            Assert.True(yFound, "Y coordinate bytes not found in COSE_Key CBOR.");
        }

        [Fact]
        public void Encode_MapKeysAreSorted()
        {
            // CTAP2 canonical: keys sorted by bytewise-lex of encoded form.
            // For ES256: kty(1)=0x01, alg(3)=0x03, crv(-1)=0x20, x(-2)=0x21, y(-3)=0x22
            // Sorted: 0x01 < 0x03 < 0x20 < 0x21 < 0x22
            var x = new byte[32];
            var y = new byte[32];
            var cbor = CoseKey.Encode(x, y);

            // Collect first bytes of each key encountered after the map header (0xa5).
            // Map header is 1 byte; then alternating key/value pairs.
            // We can parse minimal: after header, each pair: key (1 byte if <=0x37), then value.
            // Just verify the sequence of first key bytes is non-decreasing.
            // The 5 keys as first bytes: 0x01, 0x03, 0x20, 0x21, 0x22.
            int pos = 1; // skip map header
            byte prevKey = 0;
            for (int i = 0; i < 5; i++)
            {
                byte keyByte = cbor[pos];
                Assert.True(keyByte >= prevKey, $"Key at position {i} ({keyByte:X2}) is not >= previous key ({prevKey:X2}).");
                prevKey = keyByte;
                // Skip key (1 byte for small ints).
                pos++;
                // Skip value: bstr (0x58 0x20 + 32 bytes) or 1-byte uint/neg.
                if (cbor[pos] == 0x58)
                    pos += 2 + 32;
                else
                    pos += 1;
            }
        }

        private static bool ContainsSubarray(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }
    }
}
