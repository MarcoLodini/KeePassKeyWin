using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Threading;

namespace KeePassKeyWin.Core.Diagnostics
{
    /// <summary>
    /// Sensitivity tier for <see cref="TraceLogger.WriteLine(string, LogTier)"/>.
    /// <para>
    /// <see cref="Default"/> — always emits when file logging is enabled. Use
    /// for breadcrumbs that contain only opaque identifiers (CBOR sizes, hex
    /// prefixes, HRESULT, RPC method names, signCount).
    /// </para>
    /// <para>
    /// <see cref="Pii"/> — emits only when <c>KEEPASSKEYWIN_LOG_PLUGIN_PII=1</c>
    /// (or <c>true</c> / <c>yes</c>, case-insensitive) is set. Reserved for
    /// breadcrumbs that interpolate user-supplied identifiers (RP ID, user
    /// name).
    /// </para>
    /// <para>
    /// Independence from the sidecar's PII gate: the sidecar gates
    /// <c>extract_prompt_hint</c> behind <c>KEEPASSKEYWIN_LOG_LEVEL=debug</c>
    /// (a tracing level threshold), the plugin gates this tier behind a
    /// distinct binary <c>KEEPASSKEYWIN_LOG_PLUGIN_PII</c> env var. To capture
    /// PII-bearing breadcrumbs from <em>both</em> processes during diagnosis,
    /// set <em>both</em> env vars; setting only one captures only the matching
    /// process's PII.
    /// </para>
    /// </summary>
    public enum LogTier { Default, Pii }

    /// <summary>
    /// Opt-in file-based diagnostic logging for the plugin process.
    ///
    /// <para>
    /// Background: <see cref="System.Diagnostics.Debug.WriteLine"/> is gated by
    /// <c>[Conditional("DEBUG")]</c> and is compiled out in Release MSIX builds,
    /// so the plugin's IPC breadcrumbs are invisible during live validation
    /// unless we route them somewhere durable. Setting
    /// <c>KEEPASSKEYWIN_LOG_FILE_PLUGIN=&lt;path&gt;</c> in the user / machine
    /// environment before KeePass starts causes <see cref="WriteLine(string)"/>
    /// to append timestamped lines to that file. Unset = no file output (default).
    /// </para>
    ///
    /// <para>
    /// PII gating: <see cref="WriteLine(string, LogTier)"/> with
    /// <see cref="LogTier.Pii"/> short-circuits to a no-op (file route AND
    /// <see cref="System.Diagnostics.Debug.WriteLine"/>) unless
    /// <c>KEEPASSKEYWIN_LOG_PLUGIN_PII=1</c> is set. The check is evaluated
    /// per call so unit tests can flip the gate without an <see cref="Init"/>
    /// reset hook (env vars are process-scope so they cannot meaningfully
    /// change at runtime in production).
    /// </para>
    ///
    /// <para>
    /// Always also emits via <see cref="System.Diagnostics.Debug.WriteLine"/> so
    /// DEBUG-build behaviour is unchanged (the Debug call is a no-op in Release).
    /// PII-gated writes skip the Debug.WriteLine too, so DEBUG builds don't
    /// bypass the gate.
    /// </para>
    ///
    /// <para>
    /// Best-effort by design: filesystem and access-control errors during
    /// <see cref="Init"/> are caught and surfaced via
    /// <see cref="System.Diagnostics.Debug.WriteLine"/> only — they cannot
    /// break credential operations. Initialisation is idempotent and
    /// thread-safe; WriteLine takes a per-instance lock around the StreamWriter.
    /// </para>
    /// </summary>
    public static class TraceLogger
    {
        internal const string PiiGateEnvVar = "KEEPASSKEYWIN_LOG_PLUGIN_PII";

        private static StreamWriter? _writer;
        private static readonly object _lock = new object();
        private static int _initialized;

        /// <summary>
        /// Read <c>KEEPASSKEYWIN_LOG_FILE_PLUGIN</c> once and open the file if
        /// set. Idempotent — safe to call multiple times. Errors are caught
        /// and surfaced to <see cref="System.Diagnostics.Debug.WriteLine"/> only;
        /// the plugin remains operational without a trace sink.
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
                var piiState = IsPiiEnabled() ? "on" : "off";
                lock (_lock)
                {
                    _writer.WriteLine(
                        $"{DateTime.UtcNow:O} [trace] plugin file logging enabled — pid={pid} pii={piiState}");
                }
            }
            catch (Exception ex) when (
                ex is IOException
                || ex is UnauthorizedAccessException
                || ex is SecurityException
                || ex is ArgumentException        // invalid path characters
                || ex is NotSupportedException)   // path format not supported on this platform
            {
                // Best-effort init: swallow filesystem / access errors so the
                // plugin can still serve credential ops without a trace sink.
                // Surface the cause to DEBUG builds via Debug.WriteLine — that's
                // the only sink we know works pre-init.
                _writer = null;
                Debug.WriteLine($"[TraceLogger.Init] file open failed for KEEPASSKEYWIN_LOG_FILE_PLUGIN: {ex.GetType().Name}: {ex.Message}");
            }
        }

        /// <summary>
        /// Append a <see cref="LogTier.Default"/> line to the trace file (if
        /// initialised) and emit via <see cref="System.Diagnostics.Debug.WriteLine"/>
        /// for DEBUG builds. Safe to call before <see cref="Init"/>; lines
        /// are dropped silently.
        /// </summary>
        public static void WriteLine(string message) => WriteLine(message, LogTier.Default);

        /// <summary>
        /// Append a line at the given sensitivity tier. <see cref="LogTier.Pii"/>
        /// writes are suppressed entirely (file route AND
        /// <see cref="System.Diagnostics.Debug.WriteLine"/>) when
        /// <c>KEEPASSKEYWIN_LOG_PLUGIN_PII</c> is not truthy.
        /// </summary>
        public static void WriteLine(string message, LogTier tier)
        {
            if (tier == LogTier.Pii && !IsPiiEnabled()) return;

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
            catch (IOException)
            {
                // Best-effort — never fail an operation because of a log write.
            }
            catch (ObjectDisposedException)
            {
                // Writer closed underneath us (e.g. KeePass shutdown race) —
                // drop the line; next call will see _writer null or recover.
            }
        }

        // Read on each LogTier.Pii call rather than caching at Init: the env var
        // is process-scope so it can't change mid-run anyway, but reading
        // lazily means tests can set/clear the gate without an Init reset hook.
        internal static bool IsPiiEnabled()
        {
            var v = Environment.GetEnvironmentVariable(PiiGateEnvVar);
            if (string.IsNullOrEmpty(v)) return false;
            return v!.Equals("1", StringComparison.Ordinal)
                || v.Equals("true", StringComparison.OrdinalIgnoreCase)
                || v.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }
    }
}
