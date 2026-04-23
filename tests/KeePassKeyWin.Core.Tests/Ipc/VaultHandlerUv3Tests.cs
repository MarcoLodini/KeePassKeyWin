using System;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Tests.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    /// <summary>
    /// Tests for the Phase 5.UV.3 additive-acceptance behaviour in
    /// <see cref="VaultHandler.HandleMakeCredentialRaw"/> and
    /// <see cref="VaultHandler.HandleGetAssertionRaw"/>.
    ///
    /// <para>
    /// 5.UV.3 adds two optional IPC fields: <c>uvSignatureB64</c> and
    /// <c>uvBindingTier</c>. The plugin must accept dispatches with these
    /// fields present (5.UV.3+ sidecar) and without them (pre-5.UV.3
    /// sidecar interoperability). No verification is performed — that lands
    /// in 5.UV.4.
    /// </para>
    ///
    /// <para>
    /// Joined to the <c>OpSignPubKeyCache</c> collection so cache resets
    /// from <see cref="VaultHandlerSigGateTests"/> or
    /// <see cref="OpSignPubKeyCacheTests"/> cannot race with these tests.
    /// The sig gate is still live (5.UV.2), so every dispatch must include
    /// a valid <c>pbRequestSignatureB64</c>. The
    /// <see cref="MakeCredentialRawTests.BuildMakeCredentialRawParams"/> and
    /// <see cref="GetAssertionRawTests.BuildHandlerWithCredential"/> helpers
    /// are reused to avoid duplicating CBOR-building or store-seeding logic.
    /// </para>
    /// </summary>
    [Collection("OpSignPubKeyCache")]
    public class VaultHandlerUv3Tests
    {
        // ── Helpers ──────────────────────────────────────────────────────────

        /// <summary>
        /// Augments <see cref="MakeCredentialRawTests.BuildMakeCredentialRawParams"/>
        /// with optional 5.UV.3 fields and returns the completed params object.
        /// </summary>
        private static JObject MakeCredParamsWithUv(
            byte[] cborBytes,
            string? uvSigB64,
            string? uvTier)
        {
            // Reuse the 5.UV.2-compliant base (includes pbRequestSignatureB64).
            var obj = MakeCredentialRawTests.BuildMakeCredentialRawParams(cborBytes);
            if (uvSigB64 != null) obj["uvSignatureB64"] = uvSigB64;
            if (uvTier   != null) obj["uvBindingTier"]  = uvTier;
            return obj;
        }

        /// <summary>
        /// Returns a handler with one pre-seeded credential and a
        /// <c>getAssertionRaw</c> params object with optional 5.UV.3 fields.
        /// </summary>
        private static (VaultHandler handler, JObject assertParams) AssertionSetupWithUv(
            string? uvSigB64,
            string? uvTier)
        {
            var (handler, obj) = GetAssertionRawTests.BuildHandlerWithCredential();
            if (uvSigB64 != null) obj["uvSignatureB64"] = uvSigB64;
            if (uvTier   != null) obj["uvBindingTier"]  = uvTier;
            return (handler, obj);
        }

        // ── makeCredentialRaw ────────────────────────────────────────────────

        /// <summary>
        /// 5.UV.3: makeCredentialRaw accepts uvSignatureB64 + uvBindingTier
        /// without throwing. The fields are logged, not verified.
        /// </summary>
        [Fact]
        public void MakeCredentialRaw_AcceptsUvSignatureAndTier_DoesNotFail()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = new KeePassKeyWin.Core.Ipc.VaultHandler(
                new KeePassKeyWin.Core.Tests.Ipc.InMemoryPasskeyStore());

            var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
            var fakeUvSig = Convert.ToBase64String(new byte[64]); // opaque 64-zero-byte blob

            var @params = MakeCredParamsWithUv(cborBytes,
                uvSigB64: fakeUvSig,
                uvTier:   "v2_experimental");

            // Must not throw; must return a result with the 'cbor' field.
            var result = handler.Handle("keepasskeywin.makeCredentialRaw", @params);
            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.True(result!["cbor"]!.Value<string>()!.Length > 0);
        }

        /// <summary>
        /// 5.UV.3: makeCredentialRaw from a pre-5.UV.3 sidecar (absent
        /// uvSignatureB64 and uvBindingTier) must still succeed — absent
        /// fields are tolerated for interoperability.
        /// </summary>
        [Fact]
        public void MakeCredentialRaw_AcceptsAbsentUvFields_DoesNotFail()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = new KeePassKeyWin.Core.Ipc.VaultHandler(
                new KeePassKeyWin.Core.Tests.Ipc.InMemoryPasskeyStore());

            var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();

            // No uvSignatureB64, no uvBindingTier — pre-5.UV.3 sidecar shape.
            var @params = MakeCredParamsWithUv(cborBytes, uvSigB64: null, uvTier: null);

            var result = handler.Handle("keepasskeywin.makeCredentialRaw", @params);
            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }

        // ── getAssertionRaw ──────────────────────────────────────────────────

        /// <summary>
        /// 5.UV.3: getAssertionRaw accepts uvSignatureB64 + uvBindingTier
        /// without throwing. The fields are logged, not verified.
        /// </summary>
        [Fact]
        public void GetAssertionRaw_AcceptsUvSignatureAndTier_DoesNotFail()
        {
            var fakeUvSig = Convert.ToBase64String(new byte[64]);
            var (handler, assertParams) = AssertionSetupWithUv(
                uvSigB64: fakeUvSig,
                uvTier:   "v2_experimental");

            var result = handler.Handle("keepasskeywin.getAssertionRaw", assertParams);
            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.True(result!["cbor"]!.Value<string>()!.Length > 0);
        }

        /// <summary>
        /// 5.UV.3: getAssertionRaw from a pre-5.UV.3 sidecar (absent
        /// uvSignatureB64 and uvBindingTier) must still succeed — absent
        /// fields are tolerated for interoperability.
        /// </summary>
        [Fact]
        public void GetAssertionRaw_AcceptsAbsentUvFields_DoesNotFail()
        {
            var (handler, assertParams) = AssertionSetupWithUv(uvSigB64: null, uvTier: null);

            var result = handler.Handle("keepasskeywin.getAssertionRaw", assertParams);
            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }
    }
}
