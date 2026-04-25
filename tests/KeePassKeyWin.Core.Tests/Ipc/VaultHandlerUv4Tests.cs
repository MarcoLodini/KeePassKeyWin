using System;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Security;
using KeePassKeyWin.Core.Storage;
using KeePassKeyWin.Core.Tests.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    /// <summary>
    /// Tests for the Phase 5.UV.4 UV-signature verification gate in
    /// <see cref="VaultHandler.HandleMakeCredentialRaw"/> and
    /// <see cref="VaultHandler.HandleGetAssertionRaw"/>.
    ///
    /// <para>
    /// Covers the full branch table: v2_stable/v2_experimental (ECDSA verify),
    /// v1/null/"" (prompt-based fallback with cached decision), and unknown tier
    /// (fail-closed). Both raw handlers exercise the same helper; they are tested
    /// in parallel via <c>[Theory]</c>.
    /// </para>
    ///
    /// <para>
    /// Joined to <c>OpSignPubKeyCache</c> collection so cache resets here and in
    /// <see cref="VaultHandlerSigGateTests"/> / <see cref="OpSignPubKeyCacheTests"/>
    /// do not race with each other.
    /// </para>
    /// </summary>
    [Collection("OpSignPubKeyCache")]
    public class VaultHandlerUv4Tests
    {
        // ── DER conversion helper ─────────────────────────────────────────────

        /// <summary>
        /// Converts a 64-byte IEEE P1363 signature to DER <c>ECDSA-Sig-Value</c>
        /// (<c>SEQUENCE { INTEGER r, INTEGER s }</c>). Used to exercise the DER
        /// fallback path in <see cref="EcdsaVerifier.VerifyAcceptingEitherFormat"/>.
        /// </summary>
        private static byte[] P1363ToDer(byte[] p1363)
        {
            if (p1363.Length != 64) throw new ArgumentException("Expected 64-byte P1363");
            var r = StripLeadingZeros(p1363, 0,  32);
            var s = StripLeadingZeros(p1363, 32, 32);

            // DER INTEGER: if high bit set, prepend 0x00 (positive encoding).
            var rDer = (r[0] & 0x80) != 0 ? Prepend0(r) : r;
            var sDer = (s[0] & 0x80) != 0 ? Prepend0(s) : s;

            var body = new byte[2 + rDer.Length + 2 + sDer.Length];
            int pos = 0;
            body[pos++] = 0x02; body[pos++] = (byte)rDer.Length;
            Array.Copy(rDer, 0, body, pos, rDer.Length); pos += rDer.Length;
            body[pos++] = 0x02; body[pos++] = (byte)sDer.Length;
            Array.Copy(sDer, 0, body, pos, sDer.Length);

            var der = new byte[2 + body.Length];
            der[0] = 0x30; der[1] = (byte)body.Length;
            Array.Copy(body, 0, der, 2, body.Length);
            return der;
        }

        private static byte[] StripLeadingZeros(byte[] src, int offset, int length)
        {
            int start = offset;
            while (start < offset + length - 1 && src[start] == 0x00) start++;
            var result = new byte[offset + length - start];
            Array.Copy(src, start, result, 0, result.Length);
            return result;
        }

        private static byte[] Prepend0(byte[] b)
        {
            var result = new byte[b.Length + 1];
            Array.Copy(b, 0, result, 1, b.Length);
            return result;
        }

        // ── Per-method dispatch helpers ───────────────────────────────────────

        /// <summary>
        /// Builds makeCredentialRaw params with the given tier/sig overrides.
        /// <paramref name="includeTierField"/> = false → removes the field entirely.
        /// </summary>
        private static JObject MakeCredParams(
            byte[] cborBytes,
            string? tier,
            string? uvSigOverride = null,
            bool includeTierField = true,
            bool includeSigField = true)
        {
            var sig = uvSigOverride ?? OpSignTestKeys.SignAndBase64(cborBytes);
            var obj = new JObject
            {
                ["cbor"] = Convert.ToBase64String(cborBytes),
                ["uv"]   = false,
                ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(cborBytes),
            };
            if (includeSigField) obj["uvSignatureB64"] = sig;
            if (includeTierField)
                obj["uvBindingTier"] = tier != null ? (JToken)tier : JValue.CreateNull();
            return obj;
        }

        /// <summary>
        /// Returns a <see cref="VaultHandler"/> with one pre-seeded credential,
        /// and getAssertionRaw params with the given tier/sig overrides.
        /// </summary>
        private static (VaultHandler handler, JObject assertParams, byte[] cborBytes)
            AssertionSetup(
                string? tier,
                UvFallbackPrompt? prompt = null,
                string? uvSigOverride = null,
                bool includeTierField = true,
                bool includeSigField = true)
        {
            OpSignTestKeys.EnsureCachePopulated();
            var store = new InMemoryPasskeyStore();
            var handler = new VaultHandler(store, prompt ?? new UvFallbackPrompt(() => true));

            // Register a credential via makeCredentialRaw.
            var credCbor = MakeCredentialRawTests.MinimalMakeCredentialCbor();
            var credParams = MakeCredParams(credCbor, "v2_stable");
            var credResult = handler.Handle("keepasskeywin.makeCredentialRaw", credParams)!;
            var credIdB64Url = credResult["credentialIdB64Url"]!.Value<string>()!;
            var credIdRaw = Base64Url.Decode(credIdB64Url);

            var assertCbor = GetAssertionRawTests.BuildGetAssertionCbor(
                "example.com", allowListCredIds: new[] { credIdRaw });
            var sig = uvSigOverride ?? OpSignTestKeys.SignAndBase64(assertCbor);

            var obj = new JObject
            {
                ["cbor"] = Convert.ToBase64String(assertCbor),
                ["uv"]   = true,
                ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(assertCbor),
            };
            if (includeSigField) obj["uvSignatureB64"] = sig;
            if (includeTierField)
                obj["uvBindingTier"] = tier != null ? (JToken)tier : JValue.CreateNull();

            return (handler, obj, assertCbor);
        }

        // ── Case 1: v2_stable + valid sig → success ───────────────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case1_V2Stable_ValidSig_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore());
                result = handler.Handle(method, MakeCredParams(cborBytes, "v2_stable"));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_stable");
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }

        // ── Case 2: v2_experimental + valid sig → success ────────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case2_V2Experimental_ValidSig_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore());
                result = handler.Handle(method, MakeCredParams(cborBytes, "v2_experimental"));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_experimental");
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }

        // ── Case 3: v2_stable + invalid sig (mutated) → RpcException ─────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case3_V2Stable_InvalidSig_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var validSig = Convert.FromBase64String(OpSignTestKeys.SignAndBase64(cborBytes));
                validSig[32] ^= 0xFF; // mutate one byte
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v2_stable",
                            uvSigOverride: Convert.ToBase64String(validSig))));
            }
            else
            {
                var validSigB64 = string.Empty;
                var (handler, ap, assertCbor) = AssertionSetup("v2_stable", prompt: prompt);
                var sig = Convert.FromBase64String(OpSignTestKeys.SignAndBase64(assertCbor));
                sig[32] ^= 0xFF;
                ap["uvSignatureB64"] = Convert.ToBase64String(sig);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("UV signature verification failed", ex.Message);
            Assert.Equal(0, promptCalls); // prompt must NOT be invoked
        }

        // ── Case 4: v2_stable + sig absent → RpcException ────────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case4_V2Stable_SigAbsent_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                // No uvSignatureB64 field at all.
                var @params = MakeCredParams(cborBytes, "v2_stable",
                    includeSigField: false);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, @params));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_stable", prompt: prompt,
                    includeSigField: false);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("UV signature verification failed", ex.Message);
            Assert.Equal(0, promptCalls);
        }

        // ── Case 5: v2_stable + malformed base64 sig → RpcException ──────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case5_V2Stable_MalformedBase64Sig_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v2_stable",
                            uvSigOverride: "!!!NOT_BASE64!!!")));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_stable", prompt: prompt,
                    uvSigOverride: "!!!NOT_BASE64!!!");
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("UV signature verification failed", ex.Message);
            Assert.Equal(0, promptCalls);
        }

        // ── Case 6: v1 + sig present + prompt true → success, prompt once ─────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case6_V1_SigPresent_PromptTrue_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });
            var fakeSig = Convert.ToBase64String(new byte[64]);

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, "v1", uvSigOverride: fakeSig));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v1", prompt: prompt,
                    uvSigOverride: fakeSig);
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.Equal(1, promptCalls);
        }

        // ── Case 7: v1 + sig absent + prompt true → success, prompt once ──────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case7_V1_SigAbsent_PromptTrue_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, "v1", includeSigField: false));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v1", prompt: prompt,
                    includeSigField: false);
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.Equal(1, promptCalls);
        }

        // ── Case 8: v1 + prompt false → RpcException, prompt once ─────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case8_V1_PromptFalse_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return false; });

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v1", includeSigField: false)));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v1", prompt: prompt,
                    includeSigField: false);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("user declined v1-fallback UV", ex.Message);
            Assert.Equal(1, promptCalls);
        }

        // ── Case 9: two consecutive v1 ops → prompt exactly once ──────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case9_V1_TwoConsecutiveOps_PromptInvokedExactlyOnce(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                for (int i = 0; i < 2; i++)
                {
                    var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                    var result = handler.Handle(method,
                        MakeCredParams(cborBytes, "v1", includeSigField: false));
                    Assert.NotNull(result!["cbor"]?.Value<string>());
                }
            }
            else
            {
                // Use AssertionSetup which shares the same handler instance.
                var store = new InMemoryPasskeyStore();
                var handler = new VaultHandler(store, prompt);

                // Seed a credential using v2_stable (prompt not involved).
                var credCbor = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var seedResult = handler.Handle("keepasskeywin.makeCredentialRaw",
                    MakeCredParams(credCbor, "v2_stable"))!;
                var credIdRaw = Base64Url.Decode(
                    seedResult["credentialIdB64Url"]!.Value<string>()!);

                // Two getAssertion dispatches, both v1 — prompt should fire only once.
                for (int i = 0; i < 2; i++)
                {
                    var assertCbor = GetAssertionRawTests.BuildGetAssertionCbor(
                        "example.com", allowListCredIds: new[] { credIdRaw });
                    var ap = new JObject
                    {
                        ["cbor"] = Convert.ToBase64String(assertCbor),
                        ["uv"]   = true,
                        ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(assertCbor),
                        ["uvBindingTier"] = "v1",
                    };
                    var result = handler.Handle(method, ap);
                    Assert.NotNull(result!["cbor"]?.Value<string>());
                }
            }

            Assert.Equal(1, promptCalls); // decision cached after first call
        }

        // ── Case 10: tier=null (field present with null value) → v1 path ──────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case10_TierNull_TreatedAsV1(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                // null tier: field present with JSON null value.
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, tier: null, includeSigField: false));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup(tier: null, prompt: prompt,
                    includeSigField: false);
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.Equal(1, promptCalls);
        }

        // ── Case 11: tier="" (empty string) → v1 path ─────────────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case11_TierEmpty_TreatedAsV1(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, "", includeSigField: false));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("", prompt: prompt,
                    includeSigField: false);
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
            Assert.Equal(1, promptCalls);
        }

        // ── Case 12: tier="v3_future" (unknown) → fail-closed ─────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case12_UnknownTier_FailClosed(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v3_future", includeSigField: false)));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v3_future", prompt: prompt,
                    includeSigField: false);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("unknown uvBindingTier", ex.Message);
            Assert.Equal(0, promptCalls); // must NOT invoke prompt
        }

        // ── Case 13: v2_stable + valid sig + cache never populated ────────────
        // Uses bypass env var to skip the pbRequestSignature gate (which also
        // checks the cache) so we can test the UV gate in isolation.

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case13_V2Stable_CacheEmpty_Throws(string method)
        {
            // Reset cache — no pubkey installed.
            OpSignPubKeyCache.ResetForTesting();

            // Use bypass env var to skip the pbRequestSignature gate
            // (which would also fire on an empty cache before the UV gate).
            Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, "1");
            try
            {
                var fakeSig = Convert.ToBase64String(new byte[64]);

                RpcException ex;
                if (method == "keepasskeywin.makeCredentialRaw")
                {
                    var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                    var handler = new VaultHandler(new InMemoryPasskeyStore());
                    var @params = new JObject
                    {
                        ["cbor"] = Convert.ToBase64String(cborBytes),
                        ["uv"]   = false,
                        ["pbRequestSignatureB64"] = "AAAA",
                        ["uvBindingTier"] = "v2_stable",
                        ["uvSignatureB64"] = fakeSig,
                    };
                    ex = Assert.Throws<RpcException>(() => handler.Handle(method, @params));
                }
                else
                {
                    // Seed a credential while cache populated, then reset.
                    OpSignTestKeys.EnsureCachePopulated();
                    var store = new InMemoryPasskeyStore();
                    var handler = new VaultHandler(store);

                    var credCbor = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                    var seedResult = handler.Handle("keepasskeywin.makeCredentialRaw",
                        new JObject
                        {
                            ["cbor"] = Convert.ToBase64String(credCbor),
                            ["uv"]   = false,
                            ["pbRequestSignatureB64"] = "AAAA",
                            ["uvBindingTier"] = "v2_stable",
                            ["uvSignatureB64"] = OpSignTestKeys.SignAndBase64(credCbor),
                        })!;
                    var credIdRaw = Base64Url.Decode(
                        seedResult["credentialIdB64Url"]!.Value<string>()!);

                    // Now reset the cache.
                    OpSignPubKeyCache.ResetForTesting();

                    var assertCbor = GetAssertionRawTests.BuildGetAssertionCbor(
                        "example.com", allowListCredIds: new[] { credIdRaw });
                    var ap = new JObject
                    {
                        ["cbor"] = Convert.ToBase64String(assertCbor),
                        ["uv"]   = true,
                        ["pbRequestSignatureB64"] = "AAAA",
                        ["uvBindingTier"] = "v2_stable",
                        ["uvSignatureB64"] = fakeSig,
                    };
                    ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
                }

                Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
                Assert.Contains("op-sign pubkey not cached", ex.Message);
            }
            finally
            {
                Environment.SetEnvironmentVariable(BypassEnvVars.SkipPluginSigVerify, null);
                // Restore cache for subsequent tests in the collection.
                OpSignTestKeys.EnsureCachePopulated();
            }
        }

        // ── Case 14: v1 + no prompt configured → RpcException ─────────────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case14_V1_NullPrompt_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                // Handler without prompt — null.
                var handler = new VaultHandler(new InMemoryPasskeyStore());
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v1", includeSigField: false)));
            }
            else
            {
                // Need a seeded credential + no-prompt handler.
                var store = new InMemoryPasskeyStore();
                var handler = new VaultHandler(store); // null prompt

                // Seed credential (v2_stable, no prompt needed there).
                var credCbor = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var seedResult = handler.Handle("keepasskeywin.makeCredentialRaw",
                    MakeCredParams(credCbor, "v2_stable"))!;
                var credIdRaw = Base64Url.Decode(
                    seedResult["credentialIdB64Url"]!.Value<string>()!);

                var assertCbor = GetAssertionRawTests.BuildGetAssertionCbor(
                    "example.com", allowListCredIds: new[] { credIdRaw });
                var ap = new JObject
                {
                    ["cbor"] = Convert.ToBase64String(assertCbor),
                    ["uv"]   = true,
                    ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(assertCbor),
                    ["uvBindingTier"] = "v1",
                };
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("UV fallback prompt not configured", ex.Message);
        }

        // ── Case 15: v2_stable + valid IEEE P1363 sig (64 bytes) → success ────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case15_V2Stable_P1363Sig_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                // SignAndBase64 returns IEEE P1363 (64 bytes) already.
                var p1363Sig = Convert.FromBase64String(OpSignTestKeys.SignAndBase64(cborBytes));
                Assert.Equal(64, p1363Sig.Length); // confirm format in test
                var handler = new VaultHandler(new InMemoryPasskeyStore());
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, "v2_stable",
                        uvSigOverride: Convert.ToBase64String(p1363Sig)));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_stable");
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }

        // ── Case 16: v2_stable + valid DER sig → success (format-tolerance) ───

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case16_V2Stable_DerSig_Succeeds(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();

            JToken? result;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var p1363 = Convert.FromBase64String(OpSignTestKeys.SignAndBase64(cborBytes));
                var derSig = P1363ToDer(p1363);
                var handler = new VaultHandler(new InMemoryPasskeyStore());
                result = handler.Handle(method,
                    MakeCredParams(cborBytes, "v2_stable",
                        uvSigOverride: Convert.ToBase64String(derSig)));
            }
            else
            {
                var store = new InMemoryPasskeyStore();
                var handler = new VaultHandler(store, new UvFallbackPrompt(() => true));

                var credCbor = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var seedResult = handler.Handle("keepasskeywin.makeCredentialRaw",
                    MakeCredParams(credCbor, "v2_stable"))!;
                var credIdRaw = Base64Url.Decode(
                    seedResult["credentialIdB64Url"]!.Value<string>()!);

                var assertCbor = GetAssertionRawTests.BuildGetAssertionCbor(
                    "example.com", allowListCredIds: new[] { credIdRaw });
                var p1363 = Convert.FromBase64String(OpSignTestKeys.SignAndBase64(assertCbor));
                var derSig = P1363ToDer(p1363);

                var ap = new JObject
                {
                    ["cbor"] = Convert.ToBase64String(assertCbor),
                    ["uv"]   = true,
                    ["pbRequestSignatureB64"] = OpSignTestKeys.SignAndBase64(assertCbor),
                    ["uvBindingTier"] = "v2_stable",
                    ["uvSignatureB64"] = Convert.ToBase64String(derSig),
                };
                result = handler.Handle(method, ap);
            }

            Assert.NotNull(result);
            Assert.NotNull(result!["cbor"]?.Value<string>());
        }

        // ── Case 17: v2_stable + wrong-size + not parseable as DER ───────────

        [Theory]
        [InlineData("keepasskeywin.makeCredentialRaw")]
        [InlineData("keepasskeywin.getAssertionRaw")]
        public void Case17_V2Stable_WrongSizeNotDer_Throws(string method)
        {
            OpSignTestKeys.EnsureCachePopulated();
            int promptCalls = 0;
            var prompt = new UvFallbackPrompt(() => { promptCalls++; return true; });

            // 32 bytes: not 64 (fails P1363 fast path) and 0x00... (not a DER SEQUENCE).
            var garbageSig = Convert.ToBase64String(new byte[32]);

            RpcException ex;
            if (method == "keepasskeywin.makeCredentialRaw")
            {
                var cborBytes = MakeCredentialRawTests.MinimalMakeCredentialCbor();
                var handler = new VaultHandler(new InMemoryPasskeyStore(), prompt);
                ex = Assert.Throws<RpcException>(() =>
                    handler.Handle(method,
                        MakeCredParams(cborBytes, "v2_stable", uvSigOverride: garbageSig)));
            }
            else
            {
                var (handler, ap, _) = AssertionSetup("v2_stable", prompt: prompt,
                    uvSigOverride: garbageSig);
                ex = Assert.Throws<RpcException>(() => handler.Handle(method, ap));
            }

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("UV signature verification failed", ex.Message);
            Assert.Equal(0, promptCalls);
        }
    }
}
