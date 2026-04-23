using System;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Security;
using KeePassKeyWin.Core.Storage;
using KeePassKeyWin.Core.Tests.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    /// <summary>
    /// Tests for the plugin-side <c>pbRequestSignature</c> verification gate
    /// added in Phase 5.UV.2 (<see cref="VaultHandler.VerifyAndDecodeCbor"/>).
    ///
    /// <para>
    /// Joined to the <c>OpSignPubKeyCache</c> collection so cache resets here
    /// and env-var manipulations cannot race with raw-handler tests in the
    /// same assembly.
    /// </para>
    ///
    /// <para>
    /// Order of checks under test (matches the implementation):
    ///   1. Bypass env var → short-circuit accept (loud log).
    ///   2. <see cref="OpSignPubKeyCache.Current"/> null → fail-closed reject.
    ///   3. <c>pbRequestSignatureB64</c> missing or malformed → reject.
    ///   4. <see cref="EcdsaVerifier.Verify"/> false → reject.
    /// </para>
    /// </summary>
    [Collection("OpSignPubKeyCache")]
    public class VaultHandlerSigGateTests : IDisposable
    {
        private readonly string? _originalBypassEnv;

        public VaultHandlerSigGateTests()
        {
            // Capture the bypass env var so tests can mutate it without leaking
            // state to other tests in the collection.
            _originalBypassEnv = Environment.GetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify);
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, null);
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, _originalBypassEnv);
        }

        private static VaultHandler MakeHandler()
        {
            return new VaultHandler(new InMemoryPasskeyStore());
        }

        // The gate runs before any CTAP parsing, so any non-empty bytes will do
        // for sig-gate tests — we never reach the parser when the gate fires.
        // For tests that need to clear the gate (bypass / valid sig), we still
        // pass garbage cbor and assert the parser fails downstream — meaning
        // the gate already accepted.
        private static byte[] ArbitraryCbor() => new byte[] { 0xA0 }; // empty CBOR map

        // ── Cache empty, no bypass → fail-closed reject ──────────────────────

        [Fact]
        public void EmptyCache_NoBypass_Rejects_WithDistinctMessage()
        {
            OpSignPubKeyCache.ResetForTesting();
            var handler = MakeHandler();

            var cbor = ArbitraryCbor();
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(cbor),
                    ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(cbor),
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            // Message must call out the cache emptiness specifically — distinct
            // root cause from "signature verification failed" for debugging.
            Assert.Contains("op-sign pubkey not cached", ex.Message);
        }

        // ── Cache empty + bypass enabled → accept (proves short-circuit) ─────

        [Fact]
        public void EmptyCache_BypassEnabled_NoSig_GetsPastGate()
        {
            // The bypass must short-circuit BEFORE the cache check and the sig
            // check. We prove this by leaving the cache empty AND omitting
            // pbRequestSignatureB64 entirely — both would otherwise reject —
            // and asserting we get a parser-level error from the malformed
            // CBOR, which means the gate let the call through.
            OpSignPubKeyCache.ResetForTesting();
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, "1");

            var handler = MakeHandler();
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0xA5 }), // truncated map
                    // No pbRequestSignatureB64 at all — bypass must skip the check.
                }));

            // The parser's "missing required CTAP2 key" or CBOR error fires —
            // both are InvalidParams but neither contains the gate's messages.
            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.DoesNotContain("op-sign pubkey not cached", ex.Message);
            Assert.DoesNotContain("pbRequestSignatureB64", ex.Message);
            Assert.DoesNotContain("verification failed", ex.Message);
        }

        [Theory]
        [InlineData("1")]
        [InlineData("true")]
        [InlineData("TRUE")]
        [InlineData("True")]
        [InlineData("yes")]
        [InlineData("YES")]
        public void BypassEnvVar_TruthyValues_ShortCircuit(string value)
        {
            OpSignPubKeyCache.ResetForTesting();
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, value);

            var handler = MakeHandler();
            // Cache empty + no sig → would fail-closed without bypass.
            // We don't care what error fires past the gate; just that it's NOT
            // one of the gate's rejection messages.
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(new byte[] { 0xA5 }),
                }));
            Assert.DoesNotContain("op-sign pubkey not cached", ex.Message);
            Assert.DoesNotContain("pbRequestSignatureB64", ex.Message);
        }

        [Theory]
        [InlineData("0")]
        [InlineData("false")]
        [InlineData("no")]
        [InlineData("")]
        [InlineData("anything-else")]
        public void BypassEnvVar_FalsyValues_DoNotShortCircuit(string value)
        {
            OpSignPubKeyCache.ResetForTesting();
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify,
                string.IsNullOrEmpty(value) ? null : value);

            var handler = MakeHandler();
            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(ArbitraryCbor()),
                    ["pbRequestSignatureB64"] = "AAAA",
                }));
            // Without bypass, the empty cache must reject before sig verification.
            Assert.Contains("op-sign pubkey not cached", ex.Message);
        }

        // ── Cache populated, missing sig → reject ────────────────────────────

        [Fact]
        public void PopulatedCache_MissingSigParam_Rejects()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = MakeHandler();

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(ArbitraryCbor()),
                    // pbRequestSignatureB64 absent
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignatureB64 param is required", ex.Message);
        }

        [Fact]
        public void PopulatedCache_EmptySigParam_Rejects()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = MakeHandler();

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(ArbitraryCbor()),
                    ["pbRequestSignatureB64"] = "",
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignatureB64 param is required", ex.Message);
        }

        // ── Cache populated, malformed base64 sig → reject ───────────────────

        [Fact]
        public void PopulatedCache_MalformedBase64Sig_Rejects()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = MakeHandler();

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(ArbitraryCbor()),
                    ["pbRequestSignatureB64"] = "!!!not-base64!!!",
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignatureB64 is not valid base64", ex.Message);
        }

        // ── Cache populated, sig signed by wrong key → reject ────────────────

        [Fact]
        public void WrongKey_SignatureVerificationFails()
        {
            OpSignTestKeys.EnsureCachePopulated();
            var handler = MakeHandler();
            var cbor = ArbitraryCbor();

            // Sign with a fresh, unrelated key — verification must fail.
            string wrongSigB64;
            using (var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var sig = stranger.SignData(cbor, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                wrongSigB64 = Convert.ToBase64String(sig);
            }

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(cbor),
                    ["pbRequestSignatureB64"] = wrongSigB64,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignature verification failed", ex.Message);
        }

        // ── Cache populated, sig over wrong payload → reject ─────────────────

        [Fact]
        public void TamperedCbor_SignatureOverDifferentBytes_Rejects()
        {
            // Attacker scenario: signature was produced over payload A, but the
            // request sent to the plugin contains payload B. Verification must
            // catch this even though the signature is structurally valid.
            OpSignTestKeys.EnsureCachePopulated();
            var handler = MakeHandler();

            var signedBytes  = new byte[] { 0xA0, 0x00, 0x01 }; // what the sig covers
            var sentBytes    = new byte[] { 0xA0, 0x00, 0x02 }; // what we actually send
            var sigForOther  = OpSignTestKeys.SignAndBase64(signedBytes);

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(sentBytes),
                    ["pbRequestSignatureB64"] = sigForOther,
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignature verification failed", ex.Message);
        }

        // ── Cache populated with garbage → verifier rejects ──────────────────

        [Fact]
        public void GarbageInCache_VerifierReturnsFalse_Rejects()
        {
            // Cache has bytes that are not a valid BCRYPT_ECCKEY_BLOB — the
            // EcdsaVerifier returns false defensively rather than throwing,
            // and the gate must surface that as a verification failure.
            OpSignPubKeyCache.Set(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });

            var handler = MakeHandler();
            var cbor = ArbitraryCbor();

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.makeCredentialRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(cbor),
                    ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(cbor),
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("pbRequestSignature verification failed", ex.Message);
        }

        // ── Same gate behaviour applies to getAssertionRaw ───────────────────

        [Fact]
        public void GetAssertionRaw_GoesThroughSameGate_RejectsWhenCacheEmpty()
        {
            OpSignPubKeyCache.ResetForTesting();
            var handler = MakeHandler();

            var ex = Assert.Throws<RpcException>(() =>
                handler.Handle("keepasskeywin.getAssertionRaw", new JObject
                {
                    ["cbor"] = Convert.ToBase64String(ArbitraryCbor()),
                    ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(ArbitraryCbor()),
                }));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("op-sign pubkey not cached", ex.Message);
        }
    }
}
