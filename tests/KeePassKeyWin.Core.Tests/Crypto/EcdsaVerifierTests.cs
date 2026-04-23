using System;
using System.Security.Cryptography;
using KeePassKeyWin.Core.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Crypto
{
    /// <summary>
    /// Unit tests for <see cref="EcdsaVerifier"/> using NIST-vetted key material
    /// from RFC 6979 §A.2.5 (ECDSA, 256 Bits, SHA-256) plus live-generated signatures.
    ///
    /// <para>
    /// <b>On static vectors vs live-generated:</b> RFC 6979 §A.2.5 provides deterministic
    /// <c>(r, s)</c> values for a given private key, but those values rely on RFC 6979's
    /// deterministic nonce derivation. .NET's <c>ECDsa.SignData</c> uses the OS random-
    /// nonce ECDSA (FIPS 186-4 §B.5.2), not RFC 6979. Consequently, the signature bytes
    /// differ from the RFC table — a different valid ECDSA signature for the same key.
    /// </para>
    ///
    /// <para>
    /// The test strategy: use the RFC 6979 §A.2.5 private key (fixed, NIST P-256) to
    /// sign the message at test time, then verify using <see cref="EcdsaVerifier"/>.
    /// This exercises the full verifier path against NIST-approved key material.
    /// The tampered-payload/signature/wrong-key cases derive all inputs from the same
    /// signed blob, so each test is self-contained.
    /// </para>
    ///
    /// <para>
    /// RFC 6979 §A.2.5 fixed key material:
    /// <code>
    ///   d  = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    ///   Ux = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
    ///   Uy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
    /// </code>
    /// </para>
    /// </summary>
    public class EcdsaVerifierTests
    {
        // ── RFC 6979 §A.2.5 key material (NIST P-256) ────────────────────────────

        // Public key coordinates (big-endian, 32 bytes each).
        private static readonly byte[] Rfc6979_Ux = HexToBytes(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
        private static readonly byte[] Rfc6979_Uy = HexToBytes(
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");

        // Private key scalar d (32 bytes, big-endian).
        private static readonly byte[] Rfc6979_D = HexToBytes(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

        // The signed message.
        private static readonly byte[] TestMessage =
            System.Text.Encoding.UTF8.GetBytes("sample");

        // Build a pre-signed (pubKeyBlob, p1363Sig) pair using the RFC key.
        // Called once per test via helper; signing is non-deterministic but the key is fixed.
        private static (byte[] pubKeyBlob, byte[] signature) SignWithRfc6979Key(byte[] payload)
        {
            using var ecdsaPriv = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = Rfc6979_D,
                Q = new ECPoint { X = Rfc6979_Ux, Y = Rfc6979_Uy },
            });
            var sig = ecdsaPriv.SignData(payload, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var blob = BuildP256PublicKeyBlob(Rfc6979_Ux, Rfc6979_Uy);
            return (blob, sig);
        }

        // ── Happy-path verification (NIST key material) ───────────────────────────

        /// <summary>
        /// Sign a payload with the RFC 6979 §A.2.5 private key (NIST P-256) and
        /// verify using <see cref="EcdsaVerifier"/>. Proves the verifier accepts a
        /// valid signature from a NIST-vetted key.
        /// </summary>
        [Fact]
        public void Verify_ValidSignature_ReturnsTrue()
        {
            var (pubKeyBlob, signature) = SignWithRfc6979Key(TestMessage);

            bool result = EcdsaVerifier.Verify(pubKeyBlob, TestMessage, signature);

            Assert.True(result, "Valid ECDSA-P256 signature (NIST key) must verify.");
        }

        // ── Tampered payload ─────────────────────────────────────────────────────

        [Fact]
        public void Verify_TamperedPayload_ReturnsFalse()
        {
            var (pubKeyBlob, signature) = SignWithRfc6979Key(TestMessage);

            // Flip first byte of the message.
            var tampered = (byte[])TestMessage.Clone();
            tampered[0] ^= 0xFF;

            bool result = EcdsaVerifier.Verify(pubKeyBlob, tampered, signature);

            Assert.False(result, "Tampered payload must not verify.");
        }

        // ── Tampered signature ───────────────────────────────────────────────────

        [Fact]
        public void Verify_TamperedSignature_ReturnsFalse()
        {
            var (pubKeyBlob, signature) = SignWithRfc6979Key(TestMessage);

            // Flip last byte of the signature to corrupt it.
            signature[signature.Length - 1] ^= 0xFF;

            bool result = EcdsaVerifier.Verify(pubKeyBlob, TestMessage, signature);

            Assert.False(result, "Tampered signature must not verify.");
        }

        // ── Wrong public key ─────────────────────────────────────────────────────

        [Fact]
        public void Verify_WrongPubKey_ReturnsFalse()
        {
            var (_, signature) = SignWithRfc6979Key(TestMessage);

            // Generate a fresh, different key pair.
            using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var p = otherKey.ExportParameters(false);
            var wrongBlob = BuildP256PublicKeyBlob(p.Q.X!, p.Q.Y!);

            bool result = EcdsaVerifier.Verify(wrongBlob, TestMessage, signature);

            Assert.False(result, "Signature verified under a different key must return false.");
        }

        // ── Malformed blob ───────────────────────────────────────────────────────

        [Fact]
        public void Verify_MalformedBlob_TruncatedBlob_ReturnsFalse()
        {
            var (_, signature) = SignWithRfc6979Key(TestMessage);
            var truncated = new byte[40]; // less than 72-byte minimum

            bool result = EcdsaVerifier.Verify(truncated, TestMessage, signature);

            Assert.False(result, "Truncated pubkey blob must return false.");
        }

        [Fact]
        public void Verify_MalformedBlob_EmptyBlob_ReturnsFalse()
        {
            var (_, signature) = SignWithRfc6979Key(TestMessage);

            bool result = EcdsaVerifier.Verify(ReadOnlySpan<byte>.Empty, TestMessage, signature);

            Assert.False(result, "Empty pubkey blob must return false.");
        }

        [Fact]
        public void Verify_MalformedBlob_WrongMagic_ReturnsFalse()
        {
            var (pubKeyBlob, signature) = SignWithRfc6979Key(TestMessage);

            // Corrupt the magic bytes.
            pubKeyBlob[0] ^= 0xFF;

            bool result = EcdsaVerifier.Verify(pubKeyBlob, TestMessage, signature);

            Assert.False(result, "Blob with wrong magic must return false.");
        }

        // ── Empty payload / signature ─────────────────────────────────────────────

        /// <summary>
        /// Documented behavior for empty payload: returns false without throwing.
        ///
        /// SHA-256 of an empty byte string is well-defined (e8b02e5...), but the
        /// signature was produced over a different payload — so verification fails.
        /// This case documents that <see cref="EcdsaVerifier.Verify"/> does not throw
        /// for an empty payload.
        /// </summary>
        [Fact]
        public void Verify_EmptyPayload_ReturnsFalseAndDoesNotThrow()
        {
            var (pubKeyBlob, signature) = SignWithRfc6979Key(TestMessage);

            // The recorded signature was made over TestMessage, not over "".
            // It must fail, and must not throw.
            bool result = EcdsaVerifier.Verify(pubKeyBlob, ReadOnlySpan<byte>.Empty, signature);

            Assert.False(result,
                "Signature from different payload must return false for empty payload (no throw).");
        }

        [Fact]
        public void Verify_EmptySignature_ReturnsFalse()
        {
            var (pubKeyBlob, _) = SignWithRfc6979Key(TestMessage);

            bool result = EcdsaVerifier.Verify(pubKeyBlob, TestMessage, ReadOnlySpan<byte>.Empty);

            Assert.False(result, "Empty signature must return false.");
        }

        // ── BCRYPT_ECCKEY_BLOB parsing (net8.0 only) ──────────────────────────────

#if !NET48
        [Fact]
        public void TryParseBcryptP256Blob_ValidBlob_ExtractsCoordinates()
        {
            var blob = BuildP256PublicKeyBlob(Rfc6979_Ux, Rfc6979_Uy);

            bool ok = EcdsaVerifier.TryParseBcryptP256Blob(blob, out var x, out var y);

            Assert.True(ok);
            Assert.Equal(Rfc6979_Ux, x);
            Assert.Equal(Rfc6979_Uy, y);
        }

        [Fact]
        public void TryParseBcryptP256Blob_WrongSize_ReturnsFalse()
        {
            bool ok = EcdsaVerifier.TryParseBcryptP256Blob(new byte[40], out var x, out var y);
            Assert.False(ok);
            Assert.Null(x);
            Assert.Null(y);
        }

        [Fact]
        public void TryParseBcryptP256Blob_WrongMagic_ReturnsFalse()
        {
            var blob = BuildP256PublicKeyBlob(Rfc6979_Ux, Rfc6979_Uy);
            blob[0] ^= 0xFF; // corrupt magic
            bool ok = EcdsaVerifier.TryParseBcryptP256Blob(blob, out _, out _);
            Assert.False(ok);
        }
#endif

        // ── Round-trip: sign locally then verify via EcdsaVerifier ──────────────

        /// <summary>
        /// Generate a fresh P-256 key pair, sign with .NET, verify with
        /// <see cref="EcdsaVerifier"/>. Complementary to the fixed-RFC-key tests.
        /// </summary>
        [Fact]
        public void Verify_RoundTrip_FreshKey_SignThenVerify_ReturnsTrue()
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var keyParams = ecdsa.ExportParameters(false);
            var pubKeyBlob = BuildP256PublicKeyBlob(keyParams.Q.X!, keyParams.Q.Y!);

            var payload = System.Text.Encoding.UTF8.GetBytes("hello KeePassKeyWin");
            var p1363Sig = ecdsa.SignData(payload, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

            bool result = EcdsaVerifier.Verify(pubKeyBlob, payload, p1363Sig);

            Assert.True(result, "Round-trip: locally signed P1363 sig must verify.");
        }

        // ── Helpers ───────────────────────────────────────────────────────────────

        /// <summary>
        /// Constructs a 72-byte <c>BCRYPT_ECCKEY_BLOB</c> for ECDSA P-256 from
        /// big-endian (X, Y) coordinates.
        ///
        /// Layout (MSDN BCRYPT_ECCKEY_BLOB):
        ///   offset  0 (u32 LE): magic = 0x31534345 (BCRYPT_ECDSA_PUBLIC_P256_MAGIC)
        ///   offset  4 (u32 LE): cbKey = 32
        ///   offset  8 (32 B)  : X (big-endian)
        ///   offset 40 (32 B)  : Y (big-endian)
        /// </summary>
        internal static byte[] BuildP256PublicKeyBlob(byte[] x, byte[] y)
        {
            if (x.Length != 32) throw new ArgumentException("X must be 32 bytes", nameof(x));
            if (y.Length != 32) throw new ArgumentException("Y must be 32 bytes", nameof(y));

            var blob = new byte[72];
            // magic = 0x31534345 in LE: bytes 0x45, 0x43, 0x53, 0x31
            blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x53; blob[3] = 0x31;
            // cbKey = 32 in LE
            blob[4] = 0x20; blob[5] = 0x00; blob[6] = 0x00; blob[7] = 0x00;
            Buffer.BlockCopy(x, 0, blob,  8, 32);
            Buffer.BlockCopy(y, 0, blob, 40, 32);
            return blob;
        }

        /// <summary>Converts an even-length uppercase hex string to a byte array.</summary>
        private static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0) throw new ArgumentException("Odd hex length", nameof(hex));
            var result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }
    }
}
