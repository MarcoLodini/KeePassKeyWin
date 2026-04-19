using System.Runtime.InteropServices;
using KeePassKeyWin.Core.Platform;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Platform
{
    public class OsVersionCheckTests
    {
        // Helpers that call the pure version-comparison path (bypasses OS detection).
        private static (bool Ok, string Reason) Check(int major, int build, int ubr)
            => OsVersionCheck.IsSupportedWindows(() => (major, 0, build, ubr));

        // --- Version comparison logic ---

        [Fact]
        public void ExactMinimum_IsSupported()
        {
            var (ok, reason) = Check(10, 26100, 6725);
            Assert.True(ok);
            Assert.Equal(string.Empty, reason);
        }

        [Fact]
        public void HigherBuild_IsSupported()
        {
            var (ok, _) = Check(10, 27000, 0);
            Assert.True(ok);
        }

        [Fact]
        public void SameBuildHigherUbr_IsSupported()
        {
            var (ok, _) = Check(10, 26100, 9999);
            Assert.True(ok);
        }

        [Fact]
        public void SameBuildLowerUbr_IsNotSupported()
        {
            var (ok, reason) = Check(10, 26100, 6724);
            Assert.False(ok);
            Assert.Contains("26100.6725", reason);
        }

        [Fact]
        public void Win10Build_IsNotSupported()
        {
            var (ok, reason) = Check(10, 19045, 0);
            Assert.False(ok);
            Assert.Contains("26100", reason);
        }

        [Fact]
        public void OldMajorVersion_IsNotSupported()
        {
            var (ok, _) = Check(6, 9200, 0);
            Assert.False(ok);
        }

        [Fact]
        public void NullFromVersionProvider_IsNotSupported()
        {
            var (ok, reason) = OsVersionCheck.IsSupportedWindows(() => null);
            Assert.False(ok);
            Assert.NotEmpty(reason);
        }

        // ReadUbrFromRegistry returns -1 as a sentinel for "UBR unreadable". We
        // don't want to hard-fail the OS check when the registry read itself
        // failed — that would silently disable KeePassKeyWin on boxes where only the
        // major+build are determinable. Gate on major+build in that case.
        [Fact]
        public void MinimumBuild_UbrUnreadable_IsSupported()
        {
            var (ok, _) = Check(10, 26100, -1);
            Assert.True(ok);
        }

        [Fact]
        public void HigherBuild_UbrUnreadable_IsSupported()
        {
            var (ok, _) = Check(10, 27000, -1);
            Assert.True(ok);
        }

        [Fact]
        public void LowerBuild_UbrUnreadable_IsNotSupported()
        {
            // UBR unreadable should not save a box that's below the minimum build.
            var (ok, reason) = Check(10, 19045, -1);
            Assert.False(ok);
            Assert.Contains("26100", reason);
        }

        [Fact]
        public void UnreadableUbr_IsRenderedAsQuestionMark_InReason()
        {
            var (_, reason) = Check(10, 19045, -1);
            Assert.Contains("10.0.19045.?", reason);
        }

        [Fact]
        public void ReasonContainsDetectedVersion_WhenTooOld()
        {
            var (_, reason) = Check(10, 22621, 3007);
            Assert.Contains("10.0.22621.3007", reason);
        }

        [Fact]
        public void ReasonContainsMinimumVersion_WhenTooOld()
        {
            var (_, reason) = Check(10, 26100, 6724);
            Assert.Contains("26100.6725", reason);
        }

        // --- Public no-arg overload: platform-aware ---

        [Fact]
        public void PublicOverload_NonWindows_ReturnsFalse()
        {
            // On Linux/macOS CI this always returns false.
            // On Windows it depends on the actual OS version.
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var (ok, reason) = OsVersionCheck.IsSupportedWindows();
                Assert.False(ok);
                Assert.Contains("Windows 11 24H2", reason);
            }
        }
    }
}
