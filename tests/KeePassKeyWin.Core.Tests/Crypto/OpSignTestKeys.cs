using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using KeePassKeyWin.Core.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Crypto
{
    /// <summary>
    /// Shared test fixture for the plugin-side op-signing keypair (5.UV.2+).
    ///
    /// <para>
    /// Generates a deterministic-per-process ECDSA-P256 keypair the first time
    /// any test asks for it, and exposes:
    ///   - <see cref="PublicKeyBlob"/> — 72-byte <c>BCRYPT_ECCKEY_BLOB</c> matching
    ///     the byte layout sent over the hello handshake.
    ///   - <see cref="SignAndBase64"/> — sign arbitrary bytes (typically the CBOR
    ///     <c>pbEncodedRequest</c>) with the matching private key, returning the
    ///     base64-std signature for use as the <c>pbRequestSignatureB64</c> param.
    ///   - <see cref="EnsureCachePopulated"/> — idempotent installer for
    ///     <see cref="OpSignPubKeyCache"/>; raw-handler tests call this so the
    ///     verification gate accepts.
    /// </para>
    ///
    /// <para>
    /// <b>Why a collection.</b> The existing <c>OpSignPubKeyCacheTests</c> resets
    /// the static cache via <c>ResetForTesting</c> on every test. xUnit runs test
    /// classes in parallel by default, so without serialization a reset could
    /// race with a raw-handler test reading the cache. The
    /// <c>OpSignPubKeyCache</c> collection (<c>DisableParallelization = true</c>)
    /// forces every cache-touching test class to run sequentially.
    /// </para>
    /// </summary>
    public static class OpSignTestKeys
    {
        private const uint BcryptEcdsaP256Magic = 0x31534345u;
        private const int  P256CoordSize = 32;

        private static readonly object _lock = new object();
        private static byte[]? _privateKeyPkcs8;
        private static byte[]? _publicKeyBlob;

        public static byte[] PublicKeyBlob
        {
            get { EnsureGenerated(); return _publicKeyBlob!; }
        }

        /// <summary>
        /// Sign <paramref name="payload"/> with the shared test private key and
        /// return the base64-std encoded IEEE P1363 signature, ready to drop
        /// into the <c>pbRequestSignatureB64</c> JSON-RPC param.
        /// </summary>
        public static string SignAndBase64(byte[] payload)
        {
            EnsureGenerated();

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(_privateKeyPkcs8!, out _);
            var sig = ecdsa.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return Convert.ToBase64String(sig);
        }

        /// <summary>
        /// Idempotently install the test public-key blob into
        /// <see cref="OpSignPubKeyCache"/>. Tests that exercise the gate's
        /// happy path call this once at setup.
        /// </summary>
        public static void EnsureCachePopulated()
        {
            EnsureGenerated();
            OpSignPubKeyCache.Set(_publicKeyBlob!);
        }

        private static void EnsureGenerated()
        {
            if (_privateKeyPkcs8 != null && _publicKeyBlob != null) return;
            lock (_lock)
            {
                if (_privateKeyPkcs8 != null && _publicKeyBlob != null) return;

                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                _privateKeyPkcs8 = ecdsa.ExportPkcs8PrivateKey();

                var p = ecdsa.ExportParameters(includePrivateParameters: false);
                var blob = new byte[8 + 2 * P256CoordSize];
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(0, 4), BcryptEcdsaP256Magic);
                BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(4, 4), (uint)P256CoordSize);
                p.Q.X!.CopyTo(blob, 8);
                p.Q.Y!.CopyTo(blob, 8 + P256CoordSize);
                _publicKeyBlob = blob;
            }
        }
    }

    /// <summary>
    /// xUnit collection that serializes every test class touching
    /// <see cref="OpSignPubKeyCache"/>. Required so the cache-resetting tests in
    /// <c>OpSignPubKeyCacheTests</c> do not race with raw-handler tests that
    /// rely on a populated cache.
    /// </summary>
    [CollectionDefinition("OpSignPubKeyCache", DisableParallelization = true)]
    public sealed class OpSignPubKeyCacheCollection { }
}
