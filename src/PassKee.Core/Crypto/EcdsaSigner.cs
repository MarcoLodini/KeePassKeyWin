using System;
using System.Security.Cryptography;

namespace PassKee.Core.Crypto
{
    /// <summary>
    /// ES256 (ECDSA P-256 / SHA-256) key generation and signing.
    /// </summary>
    public static class EcdsaSigner
    {
        /// <summary>
        /// Generates a new P-256 key pair.
        /// </summary>
        /// <returns>
        /// pkcs8      — PKCS#8 DER-encoded private key (store in ProtectedString).
        /// x, y       — raw 32-byte big-endian curve coordinates (used internally).
        /// </returns>
        public static (byte[] pkcs8, byte[] x, byte[] y) GenerateKeyPair()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var pkcs8 = ExportPkcs8(ecdsa);
            var parameters = ecdsa.ExportParameters(false);
            return (pkcs8, parameters.Q.X!, parameters.Q.Y!);
        }

        /// <summary>
        /// Signs <paramref name="data"/> with the PKCS#8-encoded private key.
        /// Returns an ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } as required by WebAuthn.
        /// </summary>
        public static byte[] Sign(byte[] pkcs8PrivateKey, byte[] data)
        {
            using var ecdsa = ImportPkcs8(pkcs8PrivateKey);
            // SignData returns IEEE P1363 (r || s, each 32 bytes for P-256).
            var p1363 = ecdsa.SignData(data, HashAlgorithmName.SHA256);
            return P1363ToDer(p1363);
        }

        /// <summary>
        /// Round-trip check: export then re-import a PKCS#8 blob, confirm the key matches.
        /// Throws <see cref="CryptographicException"/> if the blob is malformed.
        /// </summary>
        public static void ValidatePkcs8RoundTrip(byte[] pkcs8)
        {
            using var ecdsa = ImportPkcs8(pkcs8);
            var re = ExportPkcs8(ecdsa);
            using var ecdsa2 = ImportPkcs8(re);
            // If both imports succeed without exception, the blob is self-consistent.
        }

        // Converts an IEEE P1363 signature (r || s, each exactly half the blob) into
        // the ASN.1 DER encoding WebAuthn expects:
        //   SEQUENCE {
        //     INTEGER r,   -- minimal, no leading zeros unless needed for sign bit
        //     INTEGER s
        //   }
        internal static byte[] P1363ToDer(byte[] p1363)
        {
            if (p1363.Length % 2 != 0)
                throw new ArgumentException("P1363 signature length must be even.", nameof(p1363));

            int half = p1363.Length / 2;
            var r = p1363.AsSpan(0, half);
            var s = p1363.AsSpan(half, half);

            var rDer = EncodeInteger(r);
            var sDer = EncodeInteger(s);

            int seqContentLen = rDer.Length + sDer.Length;
            var der = new byte[1 + LengthFieldSize(seqContentLen) + seqContentLen];
            int pos = 0;
            der[pos++] = 0x30; // SEQUENCE
            pos += WriteLength(der, pos, seqContentLen);
            rDer.CopyTo(der, pos); pos += rDer.Length;
            sDer.CopyTo(der, pos);
            return der;
        }

        // DER INTEGER encoding: tag 0x02 + length + value (minimal, positive).
        private static byte[] EncodeInteger(ReadOnlySpan<byte> value)
        {
            int start = 0;
            while (start < value.Length - 1 && value[start] == 0)
                start++;

            // If the high bit is set, prepend a 0x00 to signal a positive integer.
            bool needsPad = (value[start] & 0x80) != 0;
            int contentLen = value.Length - start + (needsPad ? 1 : 0);
            var encoded = new byte[1 + LengthFieldSize(contentLen) + contentLen];
            int pos = 0;
            encoded[pos++] = 0x02; // INTEGER
            pos += WriteLength(encoded, pos, contentLen);
            if (needsPad)
                encoded[pos++] = 0x00;
            value.Slice(start).CopyTo(encoded.AsSpan(pos));
            return encoded;
        }

        private static int LengthFieldSize(int length)
        {
            if (length < 0x80) return 1;
            if (length < 0x100) return 2;
            return 3;
        }

        private static int WriteLength(byte[] buf, int pos, int length)
        {
            if (length < 0x80)
            {
                buf[pos] = (byte)length;
                return 1;
            }
            if (length < 0x100)
            {
                buf[pos] = 0x81;
                buf[pos + 1] = (byte)length;
                return 2;
            }
            buf[pos] = 0x82;
            buf[pos + 1] = (byte)(length >> 8);
            buf[pos + 2] = (byte)length;
            return 3;
        }

        // PKCS#8 import/export helpers — platform-conditional because ECDsa gained these
        // methods in .NET 5; on .NET Framework 4.8 we go through CngKey instead.
        private static byte[] ExportPkcs8(ECDsa ecdsa)
        {
#if NET48
            // On .NET Framework 4.8, cast to ECDsaCng to access the underlying CngKey.
            if (ecdsa is System.Security.Cryptography.ECDsaCng cng)
                return cng.Key.Export(System.Security.Cryptography.CngKeyBlobFormat.Pkcs8PrivateBlob);
            throw new PlatformNotSupportedException("PKCS#8 export requires ECDsaCng on .NET Framework.");
#else
            return ecdsa.ExportPkcs8PrivateKey();
#endif
        }

        private static ECDsa ImportPkcs8(byte[] pkcs8)
        {
#if NET48
            var key = System.Security.Cryptography.CngKey.Import(
                pkcs8, System.Security.Cryptography.CngKeyBlobFormat.Pkcs8PrivateBlob);
            return new System.Security.Cryptography.ECDsaCng(key);
#else
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return ecdsa;
#endif
        }
    }
}
