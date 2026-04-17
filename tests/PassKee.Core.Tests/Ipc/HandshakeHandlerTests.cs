using System;
using Newtonsoft.Json.Linq;
using PassKee.Core.Ipc;
using Xunit;

namespace PassKee.Core.Tests.Ipc
{
    public sealed class HandshakeHandlerTests
    {
        private static readonly string GoodPkg = HandshakeHandler.ExpectedPkgFamily;

        private static JObject Params(string pkg, string nonce) =>
            new JObject { ["clientPkgFamilyName"] = pkg, ["handshakeNonce"] = nonce };

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
    }
}
