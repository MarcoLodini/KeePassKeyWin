using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace KeePassKeyWin.Core.Diagnostics
{
    /// <summary>
    /// Opt-in file-based diagnostic logging for the plugin process.
    ///
    /// <para>
    /// Background: <see cref="System.Diagnostics.Debug.WriteLine"/> is gated by
    /// <c>[Conditional("DEBUG")]</c> and is compiled out in Release MSIX builds,
    /// so the plugin's IPC breadcrumbs are invisible during live validation
    /// unless we route them somewhere durable. Setting
    /// <c>KEEPASSKEYWIN_LOG_FILE_PLUGIN=&lt;path&gt;</c> in the user / machine
    /// environment before KeePass starts causes <see cref="WriteLine"/> to
    /// append timestamped lines to that file. Unset = no file output (default).
    /// </para>
    ///
    /// <para>
    /// Always also emits via <see cref="System.Diagnostics.Debug.WriteLine"/> so
    /// DEBUG-build behaviour is unchanged (the Debug call is a no-op in Release).
    /// </para>
    ///
    /// <para>
    /// Best-effort by design: I/O errors are swallowed so a wedged log path
    /// cannot break credential operations. Initialisation is idempotent and
    /// thread-safe; WriteLine takes a per-instance lock around the StreamWriter.
    /// </para>
    /// </summary>
    public static class TraceLogger
    {
        private static StreamWriter? _writer;
        private static readonly object _lock = new object();
        private static int _initialized;

        /// <summary>
        /// Read <c>KEEPASSKEYWIN_LOG_FILE_PLUGIN</c> once and open the file if
        /// set. Idempotent — safe to call multiple times. Errors are swallowed.
        /// </summary>
        public static void Init()
        {
            if (Interlocked.CompareExchange(ref _initialized, 1, 0) != 0) return;
            try
            {
                var path = Environment.GetEnvironmentVariable("KEEPASSKEYWIN_LOG_FILE_PLUGIN");
                if (string.IsNullOrWhiteSpace(path)) return;

                var fs = new FileStream(
                    path!,
                    FileMode.Append,
                    FileAccess.Write,
                    FileShare.ReadWrite | FileShare.Delete);
                _writer = new StreamWriter(fs) { AutoFlush = true };

                int pid;
                try { pid = Process.GetCurrentProcess().Id; } catch { pid = -1; }
                lock (_lock)
                {
                    _writer.WriteLine(
                        $"{DateTime.UtcNow:O} [trace] plugin file logging enabled — pid={pid}");
                }
            }
            catch
            {
                _writer = null;
            }
        }

        /// <summary>
        /// Append a single line to the trace file (if initialised) and emit via
        /// <see cref="System.Diagnostics.Debug.WriteLine"/> for DEBUG builds.
        /// Safe to call before <see cref="Init"/>; lines are dropped silently.
        /// </summary>
        public static void WriteLine(string message)
        {
            Debug.WriteLine(message);

            var w = _writer;
            if (w == null) return;
            try
            {
                lock (_lock)
                {
                    w.WriteLine($"{DateTime.UtcNow:O} {message}");
                }
            }
            catch
            {
                // Best-effort — never fail an operation because of a log write.
            }
        }
    }
}
