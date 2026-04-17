using System;
using System.Collections.Generic;

namespace PassKee.Core.Storage
{
    /// <summary>
    /// Abstraction over KeePass PwEntry passkey storage.
    /// The real implementation (PassKee.Plugin) writes to the open .kdbx;
    /// the in-memory test implementation stores in a dictionary.
    /// </summary>
    public interface IPasskeyStore
    {
        /// <summary>Persist a new credential. Throws if the vault is locked.</summary>
        void Add(PasskeyRecord record);

        /// <summary>Returns all credentials for the given RP ID.</summary>
        IReadOnlyList<PasskeyRecord> FindByRpId(string rpId);

        /// <summary>Returns the credential with the given Base64URL credential ID, or null.</summary>
        PasskeyRecord? FindById(string credentialId);

        /// <summary>
        /// Removes the credential with the given Base64URL ID.
        /// Returns true if found and removed; false if not found.
        /// </summary>
        bool Delete(string credentialId);

        /// <summary>Returns all stored credentials (for enumerateForSync).</summary>
        IReadOnlyList<PasskeyRecord> GetAll();

        /// <summary>True when a KeePass database is open and accessible.</summary>
        bool IsVaultOpen { get; }
    }
}
