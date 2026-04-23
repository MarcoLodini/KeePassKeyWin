using System;
using System.Security.Cryptography;

namespace KeePassKeyWin.Core.Crypto
{
    /// <summary>
    /// RS256 (RSASSA-PKCS1-v1_5 / SHA-256, COSE alg -257) key generation and signing.
    /// Key size: 2048 bits. WebAuthn de-facto minimum; balances compatibility and blob size.
    /// </summary>
    public static class RsaSigner
    {
        /// <summary>
        /// Generates a new RSA-2048 key pair.
        /// </summary>
        /// <returns>
        /// pkcs8      — PKCS#8 DER-encoded private key (store in ProtectedString).
        /// n          — raw big-endian modulus bytes (256 bytes for 2048-bit key).
        /// e          — raw big-endian exponent bytes (3 bytes for e=65537).
        /// </returns>
        public static (byte[] pkcs8, byte[] n, byte[] e) GenerateKeyPair()
        {
            using var rsa = CreateRsa();
            var pkcs8 = ExportPkcs8(rsa);
            var parameters = rsa.ExportParameters(false);
            var n = StripLeadingZero(parameters.Modulus!, 256);
            var e = StripLeadingZero(parameters.Exponent!, 0);
            return (pkcs8, n, e);
        }

        /// <summary>
        /// Signs <paramref name="data"/> with the PKCS#8-encoded private key.
        /// Returns the raw RSASSA-PKCS1-v1_5 signature bytes (no DER wrapping needed).
        /// </summary>
        public static byte[] Sign(byte[] pkcs8PrivateKey, byte[] data)
        {
            using var rsa = ImportPkcs8(pkcs8PrivateKey);
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        // Belt-and-suspenders strip of a single leading 0x00 padding byte.
        // RSAParameters returns big-endian; .NET does not add sign-extension pads for RSA,
        // but this guard survives future CNG or platform behavior changes.
        // Only strips one byte, never more — a genuine modulus top byte may be low.
        private static byte[] StripLeadingZero(byte[] bytes, int expectedLen)
        {
            if (expectedLen > 0 && bytes.Length == expectedLen + 1 && bytes[0] == 0x00)
            {
                var stripped = new byte[expectedLen];
                Array.Copy(bytes, 1, stripped, 0, expectedLen);
                return stripped;
            }
            return bytes;
        }

        private static RSA CreateRsa()
        {
#if NET48
            return new System.Security.Cryptography.RSACng(2048);
#else
            return RSA.Create(2048);
#endif
        }

        private static byte[] ExportPkcs8(RSA rsa)
        {
#if NET48
            if (rsa is System.Security.Cryptography.RSACng cng)
                return cng.Key.Export(System.Security.Cryptography.CngKeyBlobFormat.Pkcs8PrivateBlob);
            throw new PlatformNotSupportedException("PKCS#8 export requires RSACng on .NET Framework.");
#else
            return rsa.ExportPkcs8PrivateKey();
#endif
        }

        private static RSA ImportPkcs8(byte[] pkcs8)
        {
#if NET48
            var key = System.Security.Cryptography.CngKey.Import(
                pkcs8, System.Security.Cryptography.CngKeyBlobFormat.Pkcs8PrivateBlob);
            return new System.Security.Cryptography.RSACng(key);
#else
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return rsa;
#endif
        }
    }
}
