using System;
using System.Runtime.InteropServices;

namespace PassKee.Core.Platform
{
    /// <summary>
    /// Checks whether the OS meets the minimum requirement: Windows 11 24H2 build 26100.6725+.
    /// Uses RtlGetVersion via P/Invoke on Windows because Environment.OSVersion lies under
    /// .NET Framework when the app manifest lacks a Windows 10/11 compatibility entry.
    /// </summary>
    public static class OsVersionCheck
    {
        // Minimum: Win11 24H2 (build 26100), KB5068861 raises UBR to 6725.
        internal const int MinMajor    = 10;
        internal const int MinBuild    = 26100;
        internal const int MinRevision = 6725;

        public static (bool Ok, string Reason) IsSupportedWindows()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return (false, $"PassKee requires Windows 11 24H2 build {MinBuild}.{MinRevision} or newer. Non-Windows OS detected.");

            var v = GetWindowsVersion();
            if (v == null)
                return (false, $"PassKee requires Windows 11 24H2 build {MinBuild}.{MinRevision} or newer. Could not determine OS version.");

            return CheckVersion(v.Value.major, v.Value.build, v.Value.ubr);
        }

        /// <summary>
        /// Pure version-comparison entry point for unit tests. Bypasses OS detection.
        /// Pass null to simulate a version-read failure.
        /// </summary>
        internal static (bool Ok, string Reason) IsSupportedWindows(
            Func<(int major, int minor, int build, int ubr)?> getVersion)
        {
            var v = getVersion();
            if (v == null)
                return (false, $"PassKee requires Windows 11 24H2 build {MinBuild}.{MinRevision} or newer. Could not determine OS version.");

            return CheckVersion(v.Value.major, v.Value.build, v.Value.ubr);
        }

        internal static (bool Ok, string Reason) CheckVersion(int major, int build, int ubr)
        {
            // ubr == -1 means "UBR unreadable" (ReadUbrFromRegistry sentinel). Don't
            // hard-fail on something we couldn't verify — gate on major+build only.
            // A legitimate UBR of 0 is still possible on an unpatched RTM install, so
            // we distinguish "read failed" from "read returned 0" explicitly.
            var ubrFailsMinimum = ubr >= 0 && build == MinBuild && ubr < MinRevision;
            if (major < MinMajor || build < MinBuild || ubrFailsMinimum)
            {
                var detected = ubr >= 0 ? $"{major}.0.{build}.{ubr}" : $"{major}.0.{build}.?";
                return (false,
                    $"PassKee requires Windows 11 24H2 build {MinBuild}.{MinRevision} or newer. " +
                    $"Detected: {detected}");
            }
            return (true, string.Empty);
        }

        private static (int major, int minor, int build, int ubr)? GetWindowsVersion()
        {
#if NET48
            try
            {
                var info = new RtlOsVersionInfoEx();
                info.dwOSVersionInfoSize = (uint)Marshal.SizeOf(info);
                if (RtlGetVersion(ref info) != 0)
                    return null;

                // UBR (Update Build Revision) lives in the registry; RtlGetVersion doesn't expose it.
                int ubr = ReadUbrFromRegistry();
                return ((int)info.dwMajorVersion, (int)info.dwMinorVersion, (int)info.dwBuildNumber, ubr);
            }
            catch
            {
                return null;
            }
#else
            return null;
#endif
        }

#if NET48
        [DllImport("ntdll.dll", ExactSpelling = true)]
        private static extern int RtlGetVersion(ref RtlOsVersionInfoEx lpVersionInfo);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RtlOsVersionInfoEx
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public ushort wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        /// <summary>
        /// Reads HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR.
        /// Returns -1 on any read failure (key missing, value missing, wrong type,
        /// access denied). Callers must treat -1 as "unknown" — a legitimate UBR of
        /// 0 is possible on unpatched RTM installs.
        /// </summary>
        private static int ReadUbrFromRegistry()
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
                if (key == null) return -1;
                var raw = key.GetValue("UBR");
                return raw switch
                {
                    int i  => i,
                    long l => (int)l,
                    _      => -1,
                };
            }
            catch { return -1; }
        }
#endif
    }
}
