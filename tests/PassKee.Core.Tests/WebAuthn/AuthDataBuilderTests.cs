using System;
using System.Security.Cryptography;
using System.Text;
using PassKee.Core.Crypto;
using PassKee.Core.WebAuthn;
using Xunit;

namespace PassKee.Core.Tests.WebAuthn
{
    public class AuthDataBuilderTests
    {
        private static readonly string RpId = "example.com";
        private static readonly byte[] CredId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        [Fact]
        public void Build_StartsWithRpIdHash()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            var expectedHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(RpId));
            Assert.Equal(expectedHash, authData[..32]);
        }

        [Fact]
        public void Build_FlagsContainUpUvAt_WhenUserVerified()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP flag not set.");
            Assert.True((flags & 0x04) != 0, "UV flag not set.");
            Assert.True((flags & 0x40) != 0, "AT flag not set.");
        }

        [Fact]
        public void Build_FlagsNoUv_WhenNotUserVerified()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: false);

            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP flag not set.");
            Assert.True((flags & 0x04) == 0, "UV flag should not be set.");
        }

        [Fact]
        public void Build_SignCountIsZero()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            // signCount is bytes [33..36] big-endian uint32.
            Assert.Equal(0, authData[33]);
            Assert.Equal(0, authData[34]);
            Assert.Equal(0, authData[35]);
            Assert.Equal(0, authData[36]);
        }

        [Fact]
        public void Build_AaguidIs16ZeroBytes()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            // AAGUID starts at byte 37.
            for (int i = 37; i < 53; i++)
                Assert.Equal(0, authData[i]);
        }

        [Fact]
        public void Build_CredentialIdLengthAndBytesPresent()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            // credentialIdLength at bytes [53..54] big-endian uint16.
            int credIdLen = (authData[53] << 8) | authData[54];
            Assert.Equal(CredId.Length, credIdLen);

            // credentialId bytes follow at [55..55+len).
            Assert.Equal(CredId, authData[55..(55 + CredId.Length)]);
        }

        [Fact]
        public void Build_TotalLengthIsCorrect()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            var authData = AuthDataBuilder.Build(RpId, CredId, x, y, userVerified: true);

            // 32 + 1 + 4 + 16 + 2 + credId.Length + coseKey.Length
            // coseKey for P-256: 0xa5 header + 5 entries (5 small keys, 2 bstr32, 3 small values)
            // Minimum expected: 55 + CredId.Length
            Assert.True(authData.Length > 55 + CredId.Length, "authData too short to contain COSE_Key.");
        }

        [Fact]
        public void Build_NullRpId_Throws()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            Assert.Throws<ArgumentNullException>(() => AuthDataBuilder.Build(null!, CredId, x, y, userVerified: true));
        }

        [Fact]
        public void Build_EmptyCredentialId_Throws()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            Assert.Throws<ArgumentException>(() => AuthDataBuilder.Build(RpId, Array.Empty<byte>(), x, y, userVerified: true));
        }

        [Fact]
        public void BuildAssertion_Length37()
        {
            var authData = AuthDataBuilder.BuildAssertion(RpId, userVerified: true);
            Assert.Equal(37, authData.Length);
        }

        [Fact]
        public void BuildAssertion_StartsWithRpIdHash()
        {
            var authData = AuthDataBuilder.BuildAssertion(RpId, userVerified: true);
            var expectedHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(RpId));
            Assert.Equal(expectedHash, authData[..32]);
        }

        [Fact]
        public void BuildAssertion_FlagsNoAtBit()
        {
            var authData = AuthDataBuilder.BuildAssertion(RpId, userVerified: true);
            byte flags = authData[32];
            Assert.True((flags & 0x40) == 0, "AT flag must not be set in assertion authData.");
        }
    }
}
