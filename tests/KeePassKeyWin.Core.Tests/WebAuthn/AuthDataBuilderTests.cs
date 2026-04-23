using System;
using System.Security.Cryptography;
using System.Text;
using KeePassKeyWin.Core.Cbor;
using KeePassKeyWin.Core.Crypto;
using KeePassKeyWin.Core.WebAuthn;
using Xunit;

namespace KeePassKeyWin.Core.Tests.WebAuthn
{
    public class AuthDataBuilderTests
    {
        private static readonly string RpId = "example.com";
        private static readonly byte[] CredId = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        private static byte[] Es256CoseKey()
        {
            var (_, x, y) = EcdsaSigner.GenerateKeyPair();
            return CoseKey.Encode(x, y);
        }

        [Fact]
        public void Build_StartsWithRpIdHash()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            var expectedHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(RpId));
            Assert.Equal(expectedHash, authData[..32]);
        }

        [Fact]
        public void Build_FlagsContainUpUvAt_WhenUserVerified()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP flag not set.");
            Assert.True((flags & 0x04) != 0, "UV flag not set.");
            Assert.True((flags & 0x40) != 0, "AT flag not set.");
        }

        [Fact]
        public void Build_FlagsNoUv_WhenNotUserVerified()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: false);

            byte flags = authData[32];
            Assert.True((flags & 0x01) != 0, "UP flag not set.");
            Assert.True((flags & 0x04) == 0, "UV flag should not be set.");
        }

        [Fact]
        public void Build_SignCountIsZero()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            // signCount is bytes [33..36] big-endian uint32.
            Assert.Equal(0, authData[33]);
            Assert.Equal(0, authData[34]);
            Assert.Equal(0, authData[35]);
            Assert.Equal(0, authData[36]);
        }

        [Fact]
        public void Build_AaguidIs16ZeroBytes()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            // AAGUID starts at byte 37.
            for (int i = 37; i < 53; i++)
                Assert.Equal(0, authData[i]);
        }

        [Fact]
        public void Build_CredentialIdLengthAndBytesPresent()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            // credentialIdLength at bytes [53..54] big-endian uint16.
            int credIdLen = (authData[53] << 8) | authData[54];
            Assert.Equal(CredId.Length, credIdLen);

            // credentialId bytes follow at [55..55+len).
            Assert.Equal(CredId, authData[55..(55 + CredId.Length)]);
        }

        [Fact]
        public void Build_TotalLengthIsCorrect()
        {
            var authData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);

            // 32 + 1 + 4 + 16 + 2 + credId.Length + coseKey.Length
            // coseKey for P-256: 0xa5 header + 5 entries (5 small keys, 2 bstr32, 3 small values)
            // Minimum expected: 55 + CredId.Length
            Assert.True(authData.Length > 55 + CredId.Length, "authData too short to contain COSE_Key.");
        }

        [Fact]
        public void Build_NullRpId_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => AuthDataBuilder.Build(null!, CredId, Es256CoseKey(), userVerified: true));
        }

        [Fact]
        public void Build_EmptyCredentialId_Throws()
        {
            Assert.Throws<ArgumentException>(() => AuthDataBuilder.Build(RpId, Array.Empty<byte>(), Es256CoseKey(), userVerified: true));
        }

        [Fact]
        public void Build_Rs256CoseKey_ProducesLargerAuthData()
        {
            var (_, n, e) = RsaSigner.GenerateKeyPair();
            var rsCoseKey = CoseKey.EncodeRsa(n, e);
            var authData = AuthDataBuilder.Build(RpId, CredId, rsCoseKey, userVerified: true);

            // RS256 COSE_Key is ~270 B vs ~77 B for ES256 — just verify authData is longer.
            var es256AuthData = AuthDataBuilder.Build(RpId, CredId, Es256CoseKey(), userVerified: true);
            Assert.True(authData.Length > es256AuthData.Length, "RS256 authData should be larger than ES256 authData.");
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
