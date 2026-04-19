using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KeePassKeyWin.Core.Ipc
{
    /// <summary>
    /// Line-delimited JSON-RPC 2.0 server over a named pipe.
    /// One server instance per plugin session; single-connection at a time (v1 single-instance design).
    ///
    /// Callers supply a <see cref="MethodDispatcher"/> delegate that receives the parsed request,
    /// the per-connection context, and returns a result JToken (or throws to produce an error).
    ///
    /// Windows-only at runtime (named pipes and ACLs). Compiles on any platform.
    /// Tests that exercise the pipe must be conditionally skipped on non-Windows.
    /// </summary>
    public sealed class PipeServer : IDisposable
    {
        // Delegate type for RPC method handlers registered externally.
        // Return value becomes the JSON-RPC "result".
        // Throw RpcException to produce a structured error response.
        public delegate JToken? MethodDispatcher(
            JsonRpcRequest request,
            ConnectionContext context);

        public readonly string PipeName;

        private readonly MethodDispatcher _dispatcher;
        private Thread? _listenerThread;
        private volatile bool _stopping;
        private NamedPipeServerStream? _currentStream;

        public PipeServer(string pipeName, MethodDispatcher dispatcher)
        {
            PipeName = pipeName ?? throw new ArgumentNullException(nameof(pipeName));
            _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        }

        /// <summary>
        /// Starts the listener on a background thread.
        /// Returns false if the pipe name is already taken (second-instance detection).
        /// </summary>
        public bool TryStart()
        {
#if WINDOWS
            // ACL: restrict pipe to the current user SID only.
            var security = new System.IO.Pipes.PipeSecurity();
            var sid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.SelfSid,
                System.Security.Principal.WindowsIdentity.GetCurrent().User);
            security.AddAccessRule(new System.IO.Pipes.PipeAccessRule(
                System.Security.Principal.WindowsIdentity.GetCurrent().User,
                System.IO.Pipes.PipeRights.FullControl,
                System.Security.AccessControl.AccessControlType.Allow));
#endif
            try
            {
#if WINDOWS
                _currentStream = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    1,                          // single simultaneous connection (single-instance v1)
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    0, 0,
                    security);
#else
                _currentStream = new NamedPipeServerStream(
                    PipeName,
                    PipeDirection.InOut,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);
#endif
            }
            catch (IOException)
            {
                // Another instance already owns this pipe name — stay passive.
                return false;
            }

            _listenerThread = new Thread(ListenerLoop) { IsBackground = true, Name = "KeePassKeyWin.PipeServer" };
            _listenerThread.Start();
            return true;
        }

        public void Stop()
        {
            _stopping = true;
            try { _currentStream?.Dispose(); } catch { }
        }

        public void Dispose() => Stop();

        private void ListenerLoop()
        {
            while (!_stopping)
            {
                var stream = _currentStream;
                if (stream == null) break;

                try
                {
                    stream.WaitForConnection();
                }
                catch (Exception) when (_stopping)
                {
                    break;
                }
                catch (Exception)
                {
                    break;
                }

                var context = new ConnectionContext();
                try
                {
                    ServeConnection(stream, context);
                }
                catch (Exception)
                {
                    // Connection ended; loop back to wait for the next client.
                }

                stream.Disconnect();
            }
        }

        private void ServeConnection(NamedPipeServerStream stream, ConnectionContext context)
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 4096, leaveOpen: true);
            using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), bufferSize: 4096, leaveOpen: true)
            {
                AutoFlush = true,
                NewLine = "\n"
            };

            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                var response = ProcessLine(line, context);
                var json = JsonConvert.SerializeObject(response, Formatting.None);
                writer.WriteLine(json);
            }
        }

        private JsonRpcResponse ProcessLine(string line, ConnectionContext context)
        {
            JsonRpcRequest? request = null;
            try
            {
                request = JsonConvert.DeserializeObject<JsonRpcRequest>(line);
                if (request == null || string.IsNullOrEmpty(request.Method))
                    return ErrorResponse(null, RpcErrorCode.InvalidRequest, "Invalid Request");
            }
            catch (JsonException ex)
            {
                return ErrorResponse(null, RpcErrorCode.ParseError, "Parse error: " + ex.Message);
            }

            try
            {
                var result = _dispatcher(request, context);
                return new JsonRpcResponse { Id = request.Id, Result = result ?? JValue.CreateNull() };
            }
            catch (RpcException ex)
            {
                return ErrorResponse(request.Id, ex.Code, ex.Message, ex.Data);
            }
            catch (Exception ex)
            {
                return ErrorResponse(request.Id, RpcErrorCode.InternalError, "Internal error: " + ex.Message);
            }
        }

        private static JsonRpcResponse ErrorResponse(JToken? id, int code, string message, JToken? data = null)
        {
            return new JsonRpcResponse
            {
                Id = id,
                Error = new JsonRpcError { Code = code, Message = message, Data = data }
            };
        }
    }

    // Thrown by method handlers to produce a structured JSON-RPC error response.
    public sealed class RpcException : Exception
    {
        public int Code { get; }
        public new JToken? Data { get; }

        public RpcException(int code, string message, JToken? data = null)
            : base(message)
        {
            Code = code;
            Data = data;
        }
    }
}
