using System;

namespace KeePassKeyWin.Core.Cbor
{
    /// <summary>
    /// COSE_Key encoding for ES256 (ECDSA P-256, COSE alg -7) and RS256 (RSA-2048, COSE alg -257).
    /// Produces the CTAP2-canonical CBOR representation stored in PwEntry Binaries.
    /// </summary>
    public static class CoseKey
    {
        // COSE key type parameters (RFC 9052 Table 2 / IANA COSE Key Type registry).
        private const int KtyLabel = 1;    // Key Type
        private const int AlgLabel = 3;    // Algorithm
        private const int CrvLabel = -1;   // EC curve (EC2-specific)
        private const int XLabel   = -2;   // X coordinate
        private const int YLabel   = -3;   // Y coordinate

        // Values for ES256 P-256.
        private const int KtyEc2   = 2;    // kty = EC2
        private const int AlgEs256 = -7;   // alg = ES256
        private const int CrvP256  = 1;    // crv = P-256

        // COSE key parameters for RSA (RFC 8230 §4).
        private const int KtyRsa    = 3;    // kty = RSA
        private const int AlgRs256  = -257; // alg = RS256
        private const int NLabel    = -1;   // RSA modulus
        private const int ELabel    = -2;   // RSA exponent

        /// <summary>
        /// Encodes an EC P-256 public key as a CTAP2-canonical COSE_Key CBOR map.
        /// </summary>
        /// <param name="x">32-byte big-endian X coordinate.</param>
        /// <param name="y">32-byte big-endian Y coordinate.</param>
        public static byte[] Encode(byte[] x, byte[] y)
        {
            if (x == null || x.Length != 32) throw new ArgumentException("x must be 32 bytes.", nameof(x));
            if (y == null || y.Length != 32) throw new ArgumentException("y must be 32 bytes.", nameof(y));

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (EncodeUint(KtyLabel),     EncodeUint(KtyEc2)),
                (EncodeUint(AlgLabel),     EncodeNeg(AlgEs256)),
                (EncodeNeg(CrvLabel),      EncodeUint(CrvP256)),
                (EncodeNeg(XLabel),        EncodeBytes(x)),
                (EncodeNeg(YLabel),        EncodeBytes(y)),
            });
            return w.Encode();
        }

        /// <summary>
        /// Encodes an RSA-2048 public key as a CTAP2-canonical COSE_Key CBOR map (RFC 8230 §4).
        /// Map keys sorted bytewise-lex: kty(1)=0x01, alg(3)=0x03, n(-1)=0x20, e(-2)=0x21.
        /// </summary>
        /// <param name="n">Big-endian RSA modulus bytes (256 bytes for 2048-bit).</param>
        /// <param name="e">Big-endian RSA public exponent bytes (3 bytes for e=65537).</param>
        public static byte[] EncodeRsa(byte[] n, byte[] e)
        {
            if (n == null || n.Length == 0) throw new ArgumentException("n must not be empty.", nameof(n));
            if (e == null || e.Length == 0) throw new ArgumentException("e must not be empty.", nameof(e));

            var w = new CborWriter();
            w.WriteMap(new[]
            {
                (EncodeUint(KtyLabel),  EncodeUint(KtyRsa)),
                (EncodeUint(AlgLabel),  EncodeNeg(AlgRs256)),
                (EncodeNeg(NLabel),     EncodeBytes(n)),
                (EncodeNeg(ELabel),     EncodeBytes(e)),
            });
            return w.Encode();
        }

        private static byte[] EncodeUint(int value)
        {
            var w = new CborWriter(); w.WriteUnsignedInt((ulong)value); return w.Encode();
        }

        private static byte[] EncodeNeg(int value)
        {
            var w = new CborWriter(); w.WriteNegativeInt(value); return w.Encode();
        }

        private static byte[] EncodeBytes(byte[] bytes)
        {
            var w = new CborWriter(); w.WriteByteString(bytes); return w.Encode();
        }
    }
}
