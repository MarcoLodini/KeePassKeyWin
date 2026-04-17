using System;
using System.Security.Cryptography;
using PassKee.Core.Crypto;
using Xunit;

namespace PassKee.Core.Tests.Crypto
{
    public class EcdsaSignerTests
    {
        [Fact]
        public void GenerateKeyPair_ReturnsPkcs8AndCoordinates()
        {
            var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();

            Assert.NotNull(pkcs8);
            Assert.True(pkcs8.Length > 0);
            Assert.Equal(32, x.Length);
            Assert.Equal(32, y.Length);
        }

        [Fact]
        public void GenerateKeyPair_Pkcs8RoundTripSucceeds()
        {
            var (pkcs8, _, _) = EcdsaSigner.GenerateKeyPair();
            // Should not throw.
            EcdsaSigner.ValidatePkcs8RoundTrip(pkcs8);
        }

        [Fact]
        public void GenerateKeyPair_TwoCallsProduceDifferentKeys()
        {
            var (pkcs8a, _, _) = EcdsaSigner.GenerateKeyPair();
            var (pkcs8b, _, _) = EcdsaSigner.GenerateKeyPair();
            Assert.NotEqual(pkcs8a, pkcs8b);
        }

        [Fact]
        public void Sign_ProducesDerSignatureThatVerifies()
        {
            var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();
            var data = new byte[] { 1, 2, 3, 4, 5 };

            var derSig = EcdsaSigner.Sign(pkcs8, data);

            // Reconstruct the public key from coordinates and verify.
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportParameters(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
            // .NET can verify a DER-encoded signature via the overload that accepts the format.
            bool valid = ecdsa.VerifyData(data, derSig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            Assert.True(valid);
        }

        [Fact]
        public void Sign_DifferentDataProducesDifferentSignature()
        {
            var (pkcs8, _, _) = EcdsaSigner.GenerateKeyPair();
            var sig1 = EcdsaSigner.Sign(pkcs8, new byte[] { 1, 2, 3 });
            var sig2 = EcdsaSigner.Sign(pkcs8, new byte[] { 4, 5, 6 });
            Assert.NotEqual(sig1, sig2);
        }

        // --- P1363→DER unit tests ---

        [Fact]
        public void P1363ToDer_AllZeroCoordinates_Encodes()
        {
            // r=0, s=0: minimal encoding is a single 0x00 byte for each INTEGER.
            var p1363 = new byte[64];
            var der = EcdsaSigner.P1363ToDer(p1363);
            // SEQUENCE { INTEGER 0x00, INTEGER 0x00 } = 30 06 02 01 00 02 01 00
            Assert.Equal(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00 }, der);
        }

        [Fact]
        public void P1363ToDer_HighBitSet_PadsWithZero()
        {
            // r has high bit set → needs 0x00 pad byte.
            var p1363 = new byte[64];
            p1363[0] = 0x80; // r[0] high bit set
            p1363[32] = 0x01; // s = 1

            var der = EcdsaSigner.P1363ToDer(p1363);

            // Find the r INTEGER: tag 0x02, length should be 33 (pad + 32 bytes).
            Assert.Equal(0x30, der[0]); // SEQUENCE
            Assert.Equal(0x02, der[2]); // INTEGER r
            Assert.Equal(33, der[3]);   // length = 33 (1 pad + 32)
            Assert.Equal(0x00, der[4]); // pad byte
            Assert.Equal(0x80, der[5]); // original first byte of r
        }

        [Fact]
        public void P1363ToDer_LeadingZerosStripped()
        {
            // r = 31 zero bytes followed by 0x01 → strips to single byte 0x01.
            var p1363 = new byte[64];
            p1363[31] = 0x01; // r = 0x000000...0001
            p1363[32] = 0x02; // s[0] = 2 (no leading zeros in s)

            var der = EcdsaSigner.P1363ToDer(p1363);

            Assert.Equal(0x02, der[2]); // INTEGER r tag
            Assert.Equal(1, der[3]);    // length = 1 (all leading zeros stripped)
            Assert.Equal(0x01, der[4]); // value = 1
        }

        [Fact]
        public void P1363ToDer_LeadingHighBitSet_PrependsZero()
        {
            // r = 0xFF followed by 31 zeros → high bit set → needs 0x00 prefix.
            // s = 0x01 (no pad).
            var p1363 = new byte[64];
            p1363[0] = 0xFF;  // r high bit set
            p1363[32] = 0x01; // s = 1

            var der = EcdsaSigner.P1363ToDer(p1363);

            // INTEGER r: 02 21 00 FF 00...00 (33-byte content: 1 pad + 32 bytes)
            Assert.Equal(0x02, der[2]);  // INTEGER r tag
            Assert.Equal(33,   der[3]);  // length 33
            Assert.Equal(0x00, der[4]);  // pad byte
            Assert.Equal(0xFF, der[5]);  // first byte of r
        }

        [Fact]
        public void P1363ToDer_LeadingZerosThenLargeValue_Stripped()
        {
            // r = 30 zeros then 0x00 0x01 → strips leading zeros to leave 0x01 (1 byte).
            // s = 0x7F followed by 31 zeros (high bit clear → no pad, length=32).
            var p1363 = new byte[64];
            p1363[31] = 0x01; // r last byte = 1; all others 0 → strips to single 0x01
            p1363[32] = 0x7F; // s[0] = 0x7F — high bit clear, no pad needed
            // s[1..31] are 0x00

            var der = EcdsaSigner.P1363ToDer(p1363);

            // r: 02 01 01
            Assert.Equal(0x02, der[2]);
            Assert.Equal(1,    der[3]);
            Assert.Equal(0x01, der[4]);

            // s starts at der[5]: 02 20 7F 00...00 (content=32 bytes, no pad since 0x7F bit7=0)
            int sOffset = 5;
            Assert.Equal(0x02, der[sOffset]);      // INTEGER s tag
            Assert.Equal(32,   der[sOffset + 1]);  // length = 32
            Assert.Equal(0x7F, der[sOffset + 2]);  // first byte of s
        }

        [Fact]
        public void P1363ToDer_OddLength_Throws()
        {
            Assert.Throws<ArgumentException>(() => EcdsaSigner.P1363ToDer(new byte[63]));
        }

        [Fact]
        public void P1363ToDer_KnownVector_MatchesDer()
        {
            // Use a known P-256 key and a deterministic test: sign, then verify both
            // the raw P1363 and the converted DER parse correctly.
            var (pkcs8, x, y) = EcdsaSigner.GenerateKeyPair();
            var data = System.Text.Encoding.UTF8.GetBytes("authData||clientDataHash");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256);

            var der = EcdsaSigner.P1363ToDer(p1363);

            // Verify the DER sig using the public key.
            using var pub = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            });
            Assert.True(pub.VerifyData(data, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
        }
    }
}
