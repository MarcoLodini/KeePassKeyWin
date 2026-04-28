using System;
using KeePassKeyWin.Core.Diagnostics;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Diagnostics
{
    /// <summary>
    /// Tests for the <c>KEEPASSKEYWIN_LOG_PLUGIN_PII</c> gate added in Phase 5.UV.6.
    /// The gate is read lazily on each <c>WriteLine(_, LogTier.Pii)</c> call
    /// (no Init reset hook needed); these tests target the truthy/falsy parser.
    /// </summary>
    public class TraceLoggerTests : IDisposable
    {
        private readonly string? _originalPiiEnv;

        public TraceLoggerTests()
        {
            _originalPiiEnv = Environment.GetEnvironmentVariable(TraceLogger.PiiGateEnvVar);
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, null);
        }

        public void Dispose()
        {
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, _originalPiiEnv);
        }

        [Theory]
        [InlineData("1")]
        [InlineData("true")]
        [InlineData("TRUE")]
        [InlineData("True")]
        [InlineData("yes")]
        [InlineData("YES")]
        public void PiiGate_TruthyValues_AreEnabled(string value)
        {
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, value);
            Assert.True(TraceLogger.IsPiiEnabled());
        }

        [Theory]
        [InlineData("0")]
        [InlineData("false")]
        [InlineData("no")]
        [InlineData("anything-else")]
        [InlineData(" 1")]   // leading whitespace not accepted (deliberate strict match)
        [InlineData("1 ")]   // trailing whitespace not accepted
        public void PiiGate_FalsyValues_AreDisabled(string value)
        {
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, value);
            Assert.False(TraceLogger.IsPiiEnabled());
        }

        [Fact]
        public void PiiGate_Unset_IsDisabled()
        {
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, null);
            Assert.False(TraceLogger.IsPiiEnabled());
        }

        [Fact]
        public void PiiGate_EmptyString_IsDisabled()
        {
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, "");
            Assert.False(TraceLogger.IsPiiEnabled());
        }

        [Fact]
        public void WriteLine_Default_BindsToDefaultTier_DoesNotThrow()
        {
            // WriteLine without explicit tier must default to LogTier.Default and
            // emit unconditionally (no PII gate applied). Pre-Init the writer is
            // null so the call is a no-op past Debug.WriteLine, but the call
            // itself must not throw or short-circuit on the PII check.
            TraceLogger.WriteLine("[test] default-tier sentinel");
            // No assertion — verifying absence of exception + the default
            // overload's binding to LogTier.Default.
        }

        [Fact]
        public void WriteLine_Pii_DoesNotThrow_WhenGateOff()
        {
            // Pii-tier call with gate off must short-circuit silently.
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, null);
            TraceLogger.WriteLine("[test] pii sentinel — gate off", LogTier.Pii);
        }

        [Fact]
        public void WriteLine_Pii_DoesNotThrow_WhenGateOn()
        {
            // Pii-tier call with gate on takes the full path (Debug.WriteLine
            // + file write if _writer initialised). Pre-Init the writer is null
            // so the file branch is a no-op; the call itself must not throw.
            Environment.SetEnvironmentVariable(TraceLogger.PiiGateEnvVar, "1");
            TraceLogger.WriteLine("[test] pii sentinel — gate on", LogTier.Pii);
        }
    }
}
