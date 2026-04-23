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
