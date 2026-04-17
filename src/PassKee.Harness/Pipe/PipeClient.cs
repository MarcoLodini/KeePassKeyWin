using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PassKee.Core.Ipc;

namespace PassKee.Harness.Pipe
{
    /// <summary>
    /// JSON-RPC 2.0 client over a named pipe to the PassKee plugin.
    /// Thread-safe: serialises all sends/receives through an async lock.
    /// </summary>
    public sealed class PipeClient : IAsyncDisposable
    {
        private readonly string _pipeName;
        private NamedPipeClientStream? _stream;
        private StreamReader? _reader;
        private StreamWriter? _writer;
        private int _nextId;
        private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);

        public PipeClient(string pipeName)
        {
            _pipeName = pipeName ?? throw new ArgumentNullException(nameof(pipeName));
        }

        public async Task ConnectAsync(int timeoutMs = 5000, CancellationToken ct = default)
        {
            _stream = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await _stream.ConnectAsync(timeoutMs, ct);

            _reader = new StreamReader(_stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false,
                bufferSize: 4096, leaveOpen: true);
            _writer = new StreamWriter(_stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                bufferSize: 4096, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };
        }

        /// <summary>Sends a JSON-RPC request and waits for the response.</summary>
        public async Task<JToken?> CallAsync(string method, JToken? @params, CancellationToken ct = default)
        {
            if (_writer == null || _reader == null)
                throw new InvalidOperationException("Not connected.");

            var id = Interlocked.Increment(ref _nextId);
            var request = new JsonRpcRequest
            {
                Id = id,
                Method = method,
                Params = @params,
            };

            await _lock.WaitAsync(ct);
            try
            {
                var json = JsonConvert.SerializeObject(request, Formatting.None);
                await _writer.WriteLineAsync(json);

                var line = await _reader.ReadLineAsync();
                if (line == null)
                    throw new IOException("Pipe closed unexpectedly.");

                var response = JsonConvert.DeserializeObject<JsonRpcResponse>(line)
                    ?? throw new IOException("Received null response from pipe.");

                if (response.Error != null)
                    throw new RpcException(response.Error.Code, response.Error.Message);

                return response.Result;
            }
            finally
            {
                _lock.Release();
            }
        }

        /// <summary>Performs the passkee.hello handshake with the plugin.</summary>
        public async Task HandshakeAsync(string handshakeNonce, CancellationToken ct = default)
        {
            await CallAsync("passkee.hello", new JObject
            {
                ["clientPkgFamilyName"] = HandshakeHandler.ExpectedPkgFamily,
                ["handshakeNonce"]      = handshakeNonce,
            }, ct);
        }

        public async ValueTask DisposeAsync()
        {
            _lock.Dispose();
            if (_writer != null) await _writer.DisposeAsync();
            _reader?.Dispose();
            _stream?.Dispose();
        }
    }
}
