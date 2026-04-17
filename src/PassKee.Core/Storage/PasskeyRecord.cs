using System;

namespace PassKee.Core.Storage
{
    /// <summary>
    /// In-memory representation of one passkey credential. Mirrors the PwEntry storage schema.
    /// </summary>
    public sealed class PasskeyRecord
    {
        public string CredentialId { get; set; } = string.Empty;   // Base64URL
        public string RpId { get; set; } = string.Empty;
        public string RpName { get; set; } = string.Empty;
        public string UserHandle { get; set; } = string.Empty;     // Base64URL
        public string UserName { get; set; } = string.Empty;
        public string UserDisplayName { get; set; } = string.Empty;
        public int AlgId { get; set; } = -7;                       // COSE alg; -7 = ES256
        public string PrivateKeyPkcs8 { get; set; } = string.Empty;// Base64, protected
        public byte[] PublicKeyCose { get; set; } = Array.Empty<byte>(); // CTAP2 CBOR
        public string Transports { get; set; } = "internal";       // comma-separated
        public string Flags { get; set; } = string.Empty;          // reserved for future flags
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUsedTime { get; set; } = DateTime.MinValue;
    }
}
