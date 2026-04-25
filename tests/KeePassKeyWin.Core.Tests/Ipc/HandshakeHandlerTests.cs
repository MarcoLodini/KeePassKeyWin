using System;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Tests.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    [Collection("OpSignPubKeyCache")]
    public sealed class HandshakeHandlerTests
    {
        private static readonly string GoodPkg = HandshakeHandler.ExpectedPkgFamily;

        // Builds a valid opSignPublicKeyB64 from the shared test key.
        private static string GoodKeyB64 =>
            Convert.ToBase64String(OpSignTestKeys.PublicKeyBlob);

        private static JObject Params(string pkg, string nonce, string? opSignPubKeyB64 = null) =>
            new JObject
            {
                ["clientPkgFamilyName"] = pkg,
                ["handshakeNonce"]      = nonce,
                ["opSignPublicKeyB64"]  = opSignPubKeyB64 ?? GoodKeyB64,
            };

        [Fact]
        public void Hello_ValidNonce_SetsHandshakeComplete()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            HandshakeHandler.Handle(Params(GoodPkg, "abc123"), ctx, store);

            Assert.True(ctx.HandshakeComplete);
            Assert.Equal(GoodPkg, ctx.ClientPkgFamily);
        }

        [Fact]
        public void Hello_WrongPkg_Throws()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(Params("wrong.pkg", "abc123"), ctx, store));

            Assert.Equal(RpcErrorCode.HandshakeInvalid, ex.Code);
        }

        [Fact]
        public void Hello_WrongNonce_Throws()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(Params(GoodPkg, "wrong"), ctx, store));

            Assert.Equal(RpcErrorCode.HandshakeInvalid, ex.Code);
            Assert.False(ctx.HandshakeComplete);
        }

        [Fact]
        public void Hello_NonceIsConsumed_SecondCallFails()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            HandshakeHandler.Handle(Params(GoodPkg, "abc123"), ctx, store);

            // Second hello on same connection is also rejected.
            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(Params(GoodPkg, "abc123"), ctx, store));
            Assert.Equal(RpcErrorCode.HandshakeInvalid, ex.Code);
        }

        [Fact]
        public void Hello_MissingParams_Throws()
        {
            var store = new InMemoryNonceStore();
            var ctx = new ConnectionContext();

            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(null, ctx, store));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
        }

        // ── 5.UV.4 additions ─────────────────────────────────────────────────

        /// <summary>
        /// 5.UV.4: opSignPublicKeyB64 absent → RpcException(InvalidParams).
        /// </summary>
        [Fact]
        public void Hello_OpSignPubKeyAbsent_Throws()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            // Build params without opSignPublicKeyB64.
            var @params = new JObject
            {
                ["clientPkgFamilyName"] = GoodPkg,
                ["handshakeNonce"]      = "abc123",
            };

            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(@params, ctx, store));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("opSignPublicKeyB64", ex.Message);
        }

        /// <summary>
        /// 5.UV.4: opSignPublicKeyB64 present but not valid base64 →
        /// RpcException(InvalidParams).
        /// </summary>
        [Fact]
        public void Hello_OpSignPubKeyMalformedBase64_Throws()
        {
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            var ex = Assert.Throws<RpcException>(() =>
                HandshakeHandler.Handle(
                    Params(GoodPkg, "abc123", opSignPubKeyB64: "!!!NOT_BASE64!!!"),
                    ctx, store));

            Assert.Equal(RpcErrorCode.InvalidParams, ex.Code);
            Assert.Contains("opSignPublicKeyB64", ex.Message);
        }

        /// <summary>
        /// 5.UV.4: valid opSignPublicKeyB64 → handshake succeeds and
        /// <see cref="OpSignPubKeyCache.Current"/> is populated.
        /// </summary>
        [Fact]
        public void Hello_ValidOpSignPubKey_PopulatesCache()
        {
            OpSignPubKeyCache.ResetForTesting();
            var store = new InMemoryNonceStore();
            store.Add("abc123");
            var ctx = new ConnectionContext();

            HandshakeHandler.Handle(Params(GoodPkg, "abc123"), ctx, store);

            var cached = OpSignPubKeyCache.Current;
            Assert.NotNull(cached);
            Assert.Equal(OpSignTestKeys.PublicKeyBlob, cached!.Value.ToArray());
        }
    }
}
