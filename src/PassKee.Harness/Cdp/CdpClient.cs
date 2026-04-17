using System;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PassKee.Harness.Cdp
{
    /// <summary>
    /// Minimal Chrome DevTools Protocol client over a WebSocket.
    ///
    /// Usage:
    ///   1. Launch Chrome with --remote-debugging-port=9222
    ///   2. GET http://localhost:9222/json to find the target webSocketDebuggerUrl
    ///   3. Connect via ConnectAsync(url)
    ///   4. Call methods via CallAsync; subscribe to events via OnEvent
    /// </summary>
    public sealed class CdpClient : IAsyncDisposable
    {
        private readonly ClientWebSocket _ws = new();
        private readonly ConcurrentDictionary<int, TaskCompletionSource<JObject>> _pending = new();
        private readonly ConcurrentDictionary<string, Action<JObject>> _eventHandlers = new();
        private int _nextId;
        private CancellationTokenSource? _receiveCts;

        public async Task ConnectAsync(string webSocketUrl, CancellationToken ct = default)
        {
            await _ws.ConnectAsync(new Uri(webSocketUrl), ct);
            _receiveCts = new CancellationTokenSource();
            _ = ReceiveLoopAsync(_receiveCts.Token);
        }

        /// <summary>Calls a CDP method and returns its result object.</summary>
        public async Task<JObject> CallAsync(string method, JObject? @params = null, CancellationToken ct = default)
        {
            var id = Interlocked.Increment(ref _nextId);
            var tcs = new TaskCompletionSource<JObject>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[id] = tcs;

            var msg = JsonConvert.SerializeObject(new JObject
            {
                ["id"]     = id,
                ["method"] = method,
                ["params"] = @params ?? new JObject(),
            });

            var bytes = Encoding.UTF8.GetBytes(msg);
            await _ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, ct);

            using var reg = ct.Register(() => tcs.TrySetCanceled(ct));
            return await tcs.Task;
        }

        /// <summary>Registers a handler for a CDP event (e.g. "WebAuthn.credentialAdded").</summary>
        public void OnEvent(string eventName, Action<JObject> handler)
        {
            _eventHandlers[eventName] = handler;
        }

        private async Task ReceiveLoopAsync(CancellationToken ct)
        {
            var buf = new byte[65536];
            var sb = new StringBuilder();

            try
            {
                while (!ct.IsCancellationRequested && _ws.State == WebSocketState.Open)
                {
                    sb.Clear();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await _ws.ReceiveAsync(new ArraySegment<byte>(buf), ct);
                        sb.Append(Encoding.UTF8.GetString(buf, 0, result.Count));
                    }
                    while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close) break;

                    var obj = JsonConvert.DeserializeObject<JObject>(sb.ToString());
                    if (obj == null) continue;

                    if (obj["id"] is JToken idToken)
                    {
                        var id = idToken.Value<int>();
                        if (_pending.TryRemove(id, out var tcs))
                        {
                            if (obj["error"] is JObject err)
                                tcs.TrySetException(new Exception(err["message"]?.Value<string>() ?? "CDP error"));
                            else
                                tcs.TrySetResult((JObject)(obj["result"] ?? new JObject()));
                        }
                    }
                    else if (obj["method"] is JToken methodToken)
                    {
                        var eventName = methodToken.Value<string>()!;
                        if (_eventHandlers.TryGetValue(eventName, out var handler))
                            handler((JObject)(obj["params"] ?? new JObject()));
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[CDP] Receive loop error: {ex.Message}");
            }

            // Fail all pending calls on disconnect.
            foreach (var (_, tcs) in _pending)
                tcs.TrySetException(new IOException("CDP connection closed."));
            _pending.Clear();
        }

        public async ValueTask DisposeAsync()
        {
            _receiveCts?.Cancel();
            _receiveCts?.Dispose();
            if (_ws.State == WebSocketState.Open)
                await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None);
            _ws.Dispose();
        }
    }
}
