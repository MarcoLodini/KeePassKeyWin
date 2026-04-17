using System;
using System.Security.Cryptography;
using Microsoft.Win32;
using PassKee.Core.Ipc;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif

namespace PassKee.Plugin.Ipc
{
    /// <summary>
    /// HKCU-backed single-use nonce for the passkee.hello handshake.
    ///
    /// Registry path: HKCU\Software\PassKee\HandshakeNonce (REG_SZ, hex-encoded 32 bytes).
    /// Written at plugin startup; consumed (deleted) on first successful hello.
    /// Windows-only — call sites are guarded by OS-version check in PassKeeExt.
    /// </summary>
#if NET5_0_OR_GREATER
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
#endif
    public sealed class RegistryNonceStore : INonceStore
    {
        private const string RegPath = @"Software\PassKee";
        private const string RegValue = "HandshakeNonce";

        private string? _nonce;

        public void Initialize()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            _nonce = BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

            using var key = Registry.CurrentUser.CreateSubKey(RegPath, writable: true);
            key.SetValue(RegValue, _nonce, RegistryValueKind.String);
        }

        public bool ConsumeNonce(string nonce)
        {
            if (_nonce == null) return false;
            bool match = string.Equals(nonce, _nonce, StringComparison.OrdinalIgnoreCase);
            if (match)
            {
                _nonce = null;
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                    key?.DeleteValue(RegValue, throwOnMissingValue: false);
                }
                catch { }
            }
            return match;
        }

        public void Clear()
        {
            _nonce = null;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(RegPath, writable: true);
                key?.DeleteValue(RegValue, throwOnMissingValue: false);
            }
            catch { }
        }
    }
}
