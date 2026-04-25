using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using KeePassKeyWin.Core.Ipc;
using KeePassKeyWin.Core.Tests.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    [Collection("OpSignPubKeyCache")]
    public sealed class JsonRpcFramingTests
    {
        [Fact]
        public void Hello_ValidHandshake_ReturnsOk()
        {
            var store = new InMemoryNonceStore();
            store.Add("nonce1");
            var ctx = new ConnectionContext();

            // 5.UV.4: opSignPublicKeyB64 is now required.
            var @params = new JObject
            {
                ["clientPkgFamilyName"] = HandshakeHandler.ExpectedPkgFamily,
                ["handshakeNonce"]      = "nonce1",
                ["opSignPublicKeyB64"]  = Convert.ToBase64String(OpSignTestKeys.PublicKeyBlob),
            };

            var result = HandshakeHandler.Handle(@params, ctx, store);

            Assert.Equal("ok", result.Value<string>());
            Assert.True(ctx.HandshakeComplete);
        }

        [Fact]
        public void ErrorCodes_HaveCorrectValues()
        {
            Assert.Equal(-32700, RpcErrorCode.ParseError);
            Assert.Equal(-32600, RpcErrorCode.InvalidRequest);
            Assert.Equal(-32601, RpcErrorCode.MethodNotFound);
            Assert.Equal(-32602, RpcErrorCode.InvalidParams);
            Assert.Equal(-32603, RpcErrorCode.InternalError);
            Assert.Equal(-32000, RpcErrorCode.HandshakeRequired);
            Assert.Equal(-32001, RpcErrorCode.HandshakeInvalid);
        }

        [Fact]
        public void ConnectionContext_DefaultState_HandshakeNotComplete()
        {
            var ctx = new ConnectionContext();
            Assert.False(ctx.HandshakeComplete);
            Assert.Equal(string.Empty, ctx.ClientPkgFamily);
        }

        // Named pipe round-trip: Windows only.
        [Fact]
        public async Task PipeServer_ClientConnect_ReceivesHelloResponse()
        {
            if (!OperatingSystem.IsWindows())
                return; // Skip on Linux — pipe ACL is Windows-only.

            var nonce = "test-nonce-xyz";
            var store = new InMemoryNonceStore();
            store.Add(nonce);

            var pipeName = $"KeePassKeyWinTest.{Guid.NewGuid():N}";
            using var server = new PipeServer(pipeName, (req, ctx) =>
            {
                if (req.Method == "keepasskeywin.hello")
                    return HandshakeHandler.Handle(req.Params, ctx, store);
                throw new RpcException(RpcErrorCode.MethodNotFound, $"Method not found: {req.Method}");
            });

            Assert.True(server.TryStart());
            await Task.Delay(50); // let listener thread reach WaitForConnection

            using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut);
            await client.ConnectAsync(timeout: 2000);

            using var writer = new StreamWriter(client, new UTF8Encoding(false), 4096, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };
            using var reader = new StreamReader(client, Encoding.UTF8, false, 4096, leaveOpen: true);

            // 5.UV.4: opSignPublicKeyB64 is now required in hello.
            var req = new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "keepasskeywin.hello",
                @params = new
                {
                    clientPkgFamilyName = HandshakeHandler.ExpectedPkgFamily,
                    handshakeNonce      = nonce,
                    opSignPublicKeyB64  = Convert.ToBase64String(OpSignTestKeys.PublicKeyBlob),
                }
            };
            await writer.WriteLineAsync(JsonConvert.SerializeObject(req));

            var line = await reader.ReadLineAsync();
            Assert.NotNull(line);
            var resp = JObject.Parse(line!);
            Assert.Equal("ok", resp["result"]?.Value<string>());
            Assert.Null(resp["error"]);
        }
    }
}
