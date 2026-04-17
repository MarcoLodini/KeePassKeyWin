using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using PassKee.Core.Cbor;

namespace PassKee.Core.WebAuthn
{
    /// <summary>
    /// Constructs the authenticatorData binary structure (WebAuthn L3 §6.5.1).
    ///
    /// Layout:
    ///   rpIdHash            [32 bytes]  SHA-256 of the RP ID string
    ///   flags               [1 byte]    UP | UV | AT
    ///   signCount           [4 bytes]   always 0x00000000
    ///   aaguid              [16 bytes]  all zeros (none attestation)
    ///   credentialIdLength  [2 bytes]   big-endian uint16
    ///   credentialId        [N bytes]
    ///   credentialPublicKey [M bytes]   CTAP2-canonical COSE_Key CBOR
    /// </summary>
    public static class AuthDataBuilder
    {
        // WebAuthn flags (§6.5.1 Table 1).
        private const byte FlagUP = 0x01; // user presence
        private const byte FlagUV = 0x04; // user verification
        private const byte FlagAT = 0x40; // attested credential data included

        /// <summary>
        /// Builds authenticatorData for a MakeCredential response.
        /// </summary>
        /// <param name="rpId">The RP ID (e.g. "example.com").</param>
        /// <param name="credentialId">The raw credential ID bytes.</param>
        /// <param name="x">32-byte P-256 public key X coordinate.</param>
        /// <param name="y">32-byte P-256 public key Y coordinate.</param>
        /// <param name="userVerified">True if Windows Hello UV succeeded.</param>
        public static byte[] Build(string rpId, byte[] credentialId, byte[] x, byte[] y, bool userVerified = true)
        {
            if (rpId == null) throw new ArgumentNullException(nameof(rpId));
            if (credentialId == null || credentialId.Length == 0) throw new ArgumentException("credentialId must not be empty.", nameof(credentialId));
            if (credentialId.Length > 0xFFFF) throw new ArgumentException("credentialId exceeds maximum length of 65535.", nameof(credentialId));

            var rpIdHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rpId));

            byte flags = FlagUP | FlagAT;
            if (userVerified) flags |= FlagUV;

            var coseKey = CoseKey.Encode(x, y);

            // Total length: 32 + 1 + 4 + 16 + 2 + credId.Length + coseKey.Length
            using var ms = new MemoryStream(32 + 1 + 4 + 16 + 2 + credentialId.Length + coseKey.Length);

            ms.Write(rpIdHash, 0, 32);
            ms.WriteByte(flags);
            WriteUint32Be(ms, 0); // signCount = 0
            ms.Write(new byte[16], 0, 16); // AAGUID = all zeros
            WriteUint16Be(ms, (ushort)credentialId.Length);
            ms.Write(credentialId, 0, credentialId.Length);
            ms.Write(coseKey, 0, coseKey.Length);

            return ms.ToArray();
        }

        /// <summary>
        /// Builds authenticatorData for a GetAssertion response (no attested credential data).
        /// </summary>
        public static byte[] BuildAssertion(string rpId, bool userVerified = true)
        {
            if (rpId == null) throw new ArgumentNullException(nameof(rpId));

            var rpIdHash = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(rpId));

            byte flags = FlagUP;
            if (userVerified) flags |= FlagUV;

            using var ms = new MemoryStream(37);
            ms.Write(rpIdHash, 0, 32);
            ms.WriteByte(flags);
            WriteUint32Be(ms, 0);
            return ms.ToArray();
        }

        private static void WriteUint32Be(Stream s, uint value)
        {
            s.WriteByte((byte)(value >> 24));
            s.WriteByte((byte)(value >> 16));
            s.WriteByte((byte)(value >> 8));
            s.WriteByte((byte)value);
        }

        private static void WriteUint16Be(Stream s, ushort value)
        {
            s.WriteByte((byte)(value >> 8));
            s.WriteByte((byte)value);
        }
    }
}
