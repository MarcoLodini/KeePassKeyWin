using System;
using System.Security.Cryptography;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Crypto
{
    public class RsaSignerTests
    {
        [Fact]
        public void GenerateKeyPair_ReturnsPkcs8AndParameters()
        {
            var (pkcs8, n, e) = RsaSigner.GenerateKeyPair();

            Assert.NotNull(pkcs8);
            Assert.True(pkcs8.Length > 0);
            Assert.Equal(256, n.Length); // 2048-bit modulus = 256 bytes
            Assert.True(e.Length > 0);
        }

        [Fact]
        public void GenerateKeyPair_ModulusIs256Bytes()
        {
            var (_, n, _) = RsaSigner.GenerateKeyPair();
            Assert.Equal(256, n.Length);
        }

        [Fact]
        public void GenerateKeyPair_ExponentIs65537()
        {
            var (_, _, e) = RsaSigner.GenerateKeyPair();
            // e=65537 encodes as [0x01, 0x00, 0x01] — 3 bytes, no leading zero.
            Assert.Equal(new byte[] { 0x01, 0x00, 0x01 }, e);
        }

        [Fact]
        public void GenerateKeyPair_TwoCallsProduceDifferentKeys()
        {
            var (pkcs8a, _, _) = RsaSigner.GenerateKeyPair();
            var (pkcs8b, _, _) = RsaSigner.GenerateKeyPair();
            Assert.NotEqual(pkcs8a, pkcs8b);
        }

        [Fact]
        public void Sign_ProducesSignatureThatVerifies()
        {
            var (pkcs8, n, e) = RsaSigner.GenerateKeyPair();
            var data = new byte[] { 1, 2, 3, 4, 5 };

            var sig = RsaSigner.Sign(pkcs8, data);

            Assert.NotNull(sig);
            Assert.Equal(256, sig.Length); // RSA-2048 signature = 256 bytes

            // Verify using the public key (n, e).
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n, Exponent = e });
            bool valid = rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(valid);
        }

        [Fact]
        public void Sign_DifferentDataProducesDifferentSignature()
        {
            var (pkcs8, _, _) = RsaSigner.GenerateKeyPair();
            // RS256 (PKCS#1 v1.5) is deterministic — same data, same key → same sig.
            // Different data → different sig (deterministic but data-dependent).
            var sig1 = RsaSigner.Sign(pkcs8, new byte[] { 1, 2, 3 });
            var sig2 = RsaSigner.Sign(pkcs8, new byte[] { 4, 5, 6 });
            Assert.NotEqual(sig1, sig2);
        }

        [Fact]
        public void Sign_Rs256IsNotDerWrapped()
        {
            // RS256 output is raw signature bytes, no DER SEQUENCE wrapper.
            // A DER SEQUENCE starts with 0x30; RS256-2048 must start with a non-0x30 byte
            // in almost all cases (modulus-dependent, but statistically near-certain).
            // More reliably: the signature length must be exactly 256 bytes (no DER overhead).
            var (pkcs8, _, _) = RsaSigner.GenerateKeyPair();
            var sig = RsaSigner.Sign(pkcs8, new byte[] { 0xAA, 0xBB, 0xCC });
            Assert.Equal(256, sig.Length);
        }

        [Fact]
        public void RoundTrip_GenerateEncodeCoseKeyExtractVerify()
        {
            // Full round-trip: generate → encode COSE_Key → parse n,e back → verify signature.
            var (pkcs8, n, e) = RsaSigner.GenerateKeyPair();
            var coseKey = CoseKey.EncodeRsa(n, e);

            // Parse the COSE_Key and extract n, e.
            var reader = new CborReader(coseKey);
            int mapCount = reader.ReadMapHeader();
            byte[]? parsedN = null;
            byte[]? parsedE = null;
            for (int i = 0; i < mapCount; i++)
            {
                int mt = reader.PeekMajorType();
                if (mt == 0) // positive int key
                {
                    reader.ReadUnsignedInt(); // kty or alg label
                    reader.SkipValue();       // value
                }
                else // negative int key
                {
                    long label = reader.ReadNegativeInt();
                    if (label == -1)
                        parsedN = reader.ReadByteString();
                    else if (label == -2)
                        parsedE = reader.ReadByteString();
                    else
                        reader.SkipValue();
                }
            }

            Assert.NotNull(parsedN);
            Assert.NotNull(parsedE);
            Assert.Equal(n, parsedN);
            Assert.Equal(e, parsedE);

            // Verify a signature using the parsed public key.
            var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            var sig = RsaSigner.Sign(pkcs8, data);

            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = parsedN, Exponent = parsedE });
            Assert.True(rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }
}
