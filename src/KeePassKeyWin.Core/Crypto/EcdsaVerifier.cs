using System;
using System.Security.Cryptography;

namespace KeePassKeyWin.Core.Crypto
{
    /// <summary>
    /// ES256 (ECDSA P-256 / SHA-256) signature verification against a
    /// <c>BCRYPT_PUBLIC_KEY_BLOB</c>-encoded public key.
    ///
    /// <para>
    /// <b>Platform note</b>: This class is Windows-only in practice because the
    /// blob format (<c>BCRYPT_ECDSA_P256_MAGIC</c>) is a Windows CNG convention.
    /// On .NET Framework 4.8, <c>CngKey.Import</c> + <c>ECDsaCng</c> are used directly.
    /// On .NET 8+, the blob is parsed manually to extract the raw (X, Y) coordinates
    /// and imported via the cross-platform <c>ECDsa.ImportParameters</c> path — this
    /// lets unit tests run on Linux CI against NIST/RFC 6979 test vectors.
    /// </para>
    ///
    /// <para>
    /// <b>Signature format</b>: The Windows NCrypt API returns ECDSA signatures in
    /// IEEE P1363 raw format (<c>r || s</c>, each 32 bytes for P-256, 64 bytes total).
    /// On net48 <c>ECDsaCng.VerifyData</c> accepts this format natively.
    /// On net8.0 <c>DSASignatureFormat.IeeeP1363FixedFieldConcatenation</c> is used.
    /// </para>
    /// </summary>
    public static class EcdsaVerifier
    {
        // BCRYPT_ECDSA_P256_MAGIC = 0x31534345 ("ECS1" in little-endian ASCII).
        // Layout of a 72-byte BCRYPT_ECCKEY_BLOB for P-256:
        //   offset  0 (u32 LE): magic = 0x31534345
        //   offset  4 (u32 LE): cbKey = 32
        //   offset  8 (32 B BE): X coordinate
        //   offset 40 (32 B BE): Y coordinate
        private const uint BcryptEcdsaP256Magic = 0x31534345u;
        private const int  BcryptEcdsaP256BlobSize = 72;
        private const int  P256CoordSize = 32;

        /// <summary>
        /// Verify an ECDSA-P256 signature that may be in either IEEE P1363 raw
        /// format (64-byte <c>r || s</c>) or DER <c>ECDSA-Sig-Value</c> (typically
        /// 70–72 bytes: <c>SEQUENCE { INTEGER r, INTEGER s }</c>).
        ///
        /// <para>
        /// This is the entry point for UV response verification because the Windows
        /// <c>NCryptSignHash</c> / plugin UV path does not document which encoding
        /// <c>pbResponse</c> carries. Trying P1363 first (64-byte fast path) and
        /// falling back to DER makes the gate robust against format drift without
        /// widening the strict <c>Verify</c> path used by <c>pbRequestSignature</c>.
        /// </para>
        /// </summary>
        /// <param name="pubKeyBlob">72-byte <c>BCRYPT_ECCKEY_BLOB</c> for P-256.</param>
        /// <param name="payload">Raw bytes to verify (SHA-256 hashed internally).</param>
        /// <param name="signature">Signature in either IEEE P1363 or DER format.</param>
        /// <returns>
        /// <c>true</c> on a valid signature (in either accepted format); <c>false</c>
        /// on any verification failure. Does not throw for cryptographic failures.
        /// </returns>
        public static bool VerifyAcceptingEitherFormat(
            ReadOnlySpan<byte> pubKeyBlob,
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> signature)
        {
            if (pubKeyBlob.IsEmpty || payload.IsEmpty || signature.IsEmpty)
                return false;

            // Fast path: 64-byte IEEE P1363 (current NCrypt convention).
            if (signature.Length == 64 && Verify(pubKeyBlob, payload, signature))
                return true;

            // DER fallback: SEQUENCE { INTEGER r, INTEGER s }
            // Parse manually — System.Formats.Asn1 is not available on net48,
            // and this path is exercised defensively so simplicity beats elegance.
            if (TryDerToP1363(signature, out var p1363Sig))
                return Verify(pubKeyBlob, payload, p1363Sig);

            return false;
        }

        /// <summary>
        /// Converts a DER-encoded <c>ECDSA-Sig-Value</c> to a 64-byte IEEE P1363
        /// representation (<c>r || s</c>, each 32 bytes, left-zero-padded, high-bit
        /// padding stripped).
        /// </summary>
        internal static bool TryDerToP1363(ReadOnlySpan<byte> der, out byte[] p1363)
        {
            p1363 = Array.Empty<byte>();

            // Minimum DER SEQUENCE for two 1-byte integers = 2+2+1+2+1 = 8 bytes.
            if (der.Length < 8)
                return false;

            // SEQUENCE tag + length
            if (der[0] != 0x30)
                return false;

            int pos = 1;
            int seqLen = ReadDerLength(der, ref pos);
            if (seqLen < 0 || pos + seqLen != der.Length)
                return false;

            // First INTEGER (r)
            if (pos >= der.Length || der[pos] != 0x02) return false;
            pos++;
            int rLen = ReadDerLength(der, ref pos);
            if (rLen <= 0 || pos + rLen > der.Length) return false;
            var rBytes = der.Slice(pos, rLen);
            pos += rLen;

            // Second INTEGER (s)
            if (pos >= der.Length || der[pos] != 0x02) return false;
            pos++;
            int sLen = ReadDerLength(der, ref pos);
            if (sLen <= 0 || pos + sLen != der.Length) return false;
            var sBytes = der.Slice(pos, sLen);

            // Convert each integer: strip leading 0x00 padding, then left-pad to 32 bytes.
            var result = new byte[64];
            if (!TryFitCoord(rBytes, result, 0))  return false;
            if (!TryFitCoord(sBytes, result, 32)) return false;

            p1363 = result;
            return true;
        }

        private static int ReadDerLength(ReadOnlySpan<byte> data, ref int pos)
        {
            if (pos >= data.Length) return -1;
            byte b = data[pos++];
            if (b < 0x80) return b;          // short form
            int numBytes = b & 0x7F;
            if (numBytes == 0 || numBytes > 2 || pos + numBytes > data.Length) return -1;
            int len = 0;
            for (int i = 0; i < numBytes; i++)
                len = (len << 8) | data[pos++];
            return len;
        }

        private static bool TryFitCoord(ReadOnlySpan<byte> coord, byte[] dest, int destOffset)
        {
            // Strip DER leading-zero padding.
            int start = 0;
            while (start < coord.Length - 1 && coord[start] == 0x00)
                start++;
            var trimmed = coord.Slice(start);

            if (trimmed.Length > P256CoordSize) return false; // value too large for P-256

            // Left-pad to exactly 32 bytes (dest is already zero-initialised).
            int padding = P256CoordSize - trimmed.Length;
            trimmed.CopyTo(dest.AsSpan(destOffset + padding, trimmed.Length));
            return true;
        }

        /// <summary>
        /// Verify an ECDSA-P256 signature over SHA-256(payload) using the given
        /// <c>BCRYPT_PUBLIC_KEY_BLOB</c> pubkey bytes.
        /// </summary>
        /// <param name="pubKeyBlob">
        /// 72-byte <c>BCRYPT_ECCKEY_BLOB</c> with magic <c>0x31534345</c> (P-256 public key).
        /// </param>
        /// <param name="payload">
        /// Raw bytes over which SHA-256 is computed before verifying. An empty
        /// payload is rejected explicitly (returns false, no exception): in our
        /// use case the verifier always operates on non-empty CTAP2 request
        /// bytes, so an empty payload indicates a programmer error upstream.
        /// </param>
        /// <param name="signature">
        /// 64-byte IEEE P1363 raw signature (<c>r || s</c>, each 32 bytes).
        /// </param>
        /// <returns>
        /// <c>true</c> on a valid signature; <c>false</c> on any verification
        /// failure (bad signature, malformed pubkey blob, wrong curve, etc.).
        /// Does not throw for cryptographic failures.
        /// </returns>
        public static bool Verify(
            ReadOnlySpan<byte> pubKeyBlob,
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> signature)
        {
            // Reject obviously-bad inputs without touching crypto. Empty payload
            // is included here so the doc/code contract matches: legitimate
            // CTAP2 request bytes are never empty at this call site.
            if (pubKeyBlob.IsEmpty || payload.IsEmpty || signature.IsEmpty)
                return false;

            try
            {
#if NET48
                return VerifyNet48(pubKeyBlob, payload, signature);
#else
                return VerifyNet8Plus(pubKeyBlob, payload, signature);
#endif
            }
            catch (CryptographicException)
            {
                // Malformed key blob, bad signature encoding, or any other
                // cryptographic error: return false rather than surfacing the exception.
                return false;
            }
            catch (ArgumentException)
            {
                // Bad arguments to the underlying BCrypt/NCrypt APIs.
                return false;
            }
        }

#if NET48
        // .NET Framework 4.8: import the blob directly via CngKey (Windows-only).
        private static bool VerifyNet48(
            ReadOnlySpan<byte> pubKeyBlob,
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> signature)
        {
            // CngKey.Import requires a byte[], not Span, on net48.
            var blobArray = pubKeyBlob.ToArray();
            var key = System.Security.Cryptography.CngKey.Import(
                blobArray, System.Security.Cryptography.CngKeyBlobFormat.GenericPublicBlob);
            using var ecdsa = new System.Security.Cryptography.ECDsaCng(key);
            // ECDsaCng.VerifyData accepts IEEE P1363 (r||s) natively on net48.
            return ecdsa.VerifyData(payload.ToArray(), signature.ToArray(), HashAlgorithmName.SHA256);
        }
#else
        // .NET 8+: parse the BCRYPT_ECCKEY_BLOB manually and use the cross-platform path.
        // This allows tests to run on Linux CI without CNG.
        private static bool VerifyNet8Plus(
            ReadOnlySpan<byte> pubKeyBlob,
            ReadOnlySpan<byte> payload,
            ReadOnlySpan<byte> signature)
        {
            if (!TryParseBcryptP256Blob(pubKeyBlob, out var x, out var y))
                return false;

            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y },
            });

            return ecdsa.VerifyData(payload, signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        /// <summary>
        /// Parses a 72-byte <c>BCRYPT_ECCKEY_BLOB</c> for P-256 and extracts the
        /// raw (X, Y) coordinates as big-endian 32-byte arrays.
        /// Returns false if the blob is malformed (wrong size, wrong magic, wrong cbKey).
        /// </summary>
        internal static bool TryParseBcryptP256Blob(
            ReadOnlySpan<byte> blob,
            out byte[]? x,
            out byte[]? y)
        {
            x = null;
            y = null;

            if (blob.Length != BcryptEcdsaP256BlobSize)
                return false;

            // Read magic (u32 LE) at offset 0.
            uint magic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(blob.Slice(0, 4));
            if (magic != BcryptEcdsaP256Magic)
                return false;

            // Read cbKey (u32 LE) at offset 4.
            uint cbKey = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(blob.Slice(4, 4));
            if (cbKey != P256CoordSize)
                return false;

            x = blob.Slice(8, P256CoordSize).ToArray();
            y = blob.Slice(8 + P256CoordSize, P256CoordSize).ToArray();
            return true;
        }
#endif
    }
}
