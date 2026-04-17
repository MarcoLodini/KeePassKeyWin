using System;
using System.Collections.Generic;
using KeePass.Plugins;
using KeePassLib;
using PassKee.Core.Storage;

namespace PassKee.Plugin.Storage
{
    /// <summary>
    /// IPasskeyStore backed by a KeePass PwDatabase. Reads and writes PwEntry records
    /// in the "Passkeys" group using the storage schema defined in ARCHITECTURE.md.
    /// </summary>
    public sealed class KeePassPasskeyStore : IPasskeyStore
    {
        private const string GroupName      = "Passkeys";
        private const string KeyCredId      = "PassKee.credentialId";
        private const string KeyRpId        = "PassKee.rpId";
        private const string KeyRpName      = "PassKee.rpName";
        private const string KeyUserHandle  = "PassKee.userHandle";
        private const string KeyUserName    = "PassKee.userName";
        private const string KeyUserDisplay = "PassKee.userDisplayName";
        private const string KeyPrivateKey  = "PassKee.privateKey";
        private const string KeyAlgId       = "PassKee.algId";
        private const string KeySignCount   = "PassKee.signCount";
        private const string KeyAaguid      = "PassKee.aaguid";
        private const string BinPublicKey   = "PassKee.publicKey.cbor";

        private readonly IPluginHost _host;

        public KeePassPasskeyStore(IPluginHost host)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
        }

        public bool IsVaultOpen => _host.Database?.IsOpen == true;

        public void Add(PasskeyRecord record)
        {
            var group = EnsurePasskeysGroup();
            var entry = new PwEntry();

            entry.Strings.Set(KeyCredId,      new ProtectedString(false, record.CredentialId));
            entry.Strings.Set(KeyRpId,        new ProtectedString(false, record.RpId));
            entry.Strings.Set(KeyRpName,      new ProtectedString(false, record.RpName));
            entry.Strings.Set(KeyUserHandle,  new ProtectedString(false, record.UserHandle));
            entry.Strings.Set(KeyUserName,    new ProtectedString(false, record.UserName));
            entry.Strings.Set(KeyUserDisplay, new ProtectedString(false, record.UserDisplayName));
            entry.Strings.Set(KeyPrivateKey,  new ProtectedString(true, record.PrivateKeyPkcs8));
            entry.CustomData.Set(KeyAlgId,    record.AlgId.ToString());
            entry.CustomData.Set(KeySignCount, "0");
            entry.CustomData.Set(KeyAaguid,   "00000000000000000000000000000000");
            entry.Binaries.Set(BinPublicKey,  new ProtectedBinary(false, record.PublicKeyCose));

            // KeePass entry title for human readability.
            entry.Strings.Set("Title", new ProtectedString(false,
                $"{record.RpName} / {record.UserDisplayName}"));

            group.AddEntry(entry, bTakeOwnership: true);
        }

        public IReadOnlyList<PasskeyRecord> FindByRpId(string rpId)
        {
            var results = new List<PasskeyRecord>();
            var group = FindPasskeysGroup();
            if (group == null) return results;

            for (uint i = 0; i < group.Entries.UCount; i++)
            {
                var entry = group.Entries.GetAt(i);
                var entryRpId = entry.Strings.Get(KeyRpId)?.ReadString();
                if (string.Equals(entryRpId, rpId, StringComparison.Ordinal))
                    results.Add(EntryToRecord(entry));
            }
            return results;
        }

        public PasskeyRecord? FindById(string credentialId)
        {
            var group = FindPasskeysGroup();
            if (group == null) return null;

            for (uint i = 0; i < group.Entries.UCount; i++)
            {
                var entry = group.Entries.GetAt(i);
                var id = entry.Strings.Get(KeyCredId)?.ReadString();
                if (string.Equals(id, credentialId, StringComparison.Ordinal))
                    return EntryToRecord(entry);
            }
            return null;
        }

        public bool Delete(string credentialId)
        {
            var group = FindPasskeysGroup();
            if (group == null) return false;

            for (uint i = 0; i < group.Entries.UCount; i++)
            {
                var entry = group.Entries.GetAt(i);
                var id = entry.Strings.Get(KeyCredId)?.ReadString();
                if (string.Equals(id, credentialId, StringComparison.Ordinal))
                {
                    group.Entries.Remove(entry);
                    return true;
                }
            }
            return false;
        }

        public IReadOnlyList<PasskeyRecord> GetAll()
        {
            var results = new List<PasskeyRecord>();
            var group = FindPasskeysGroup();
            if (group == null) return results;

            for (uint i = 0; i < group.Entries.UCount; i++)
                results.Add(EntryToRecord(group.Entries.GetAt(i)));

            return results;
        }

        private PwGroup EnsurePasskeysGroup()
        {
            var db = _host.Database!;
            var root = db.RootGroup;

            for (uint i = 0; i < root.Groups.UCount; i++)
            {
                var g = root.Groups.GetAt(i);
                if (g.Name == GroupName) return g;
            }

            var newGroup = new PwGroup { Name = GroupName };
            root.AddGroup(newGroup, bTakeOwnership: true);
            return newGroup;
        }

        private PwGroup? FindPasskeysGroup()
        {
            var db = _host.Database;
            if (db == null || !db.IsOpen) return null;
            var root = db.RootGroup;

            for (uint i = 0; i < root.Groups.UCount; i++)
            {
                var g = root.Groups.GetAt(i);
                if (g.Name == GroupName) return g;
            }
            return null;
        }

        private static PasskeyRecord EntryToRecord(PwEntry entry)
            => new PasskeyRecord
            {
                CredentialId    = entry.Strings.Get(KeyCredId)?.ReadString() ?? string.Empty,
                RpId            = entry.Strings.Get(KeyRpId)?.ReadString() ?? string.Empty,
                RpName          = entry.Strings.Get(KeyRpName)?.ReadString() ?? string.Empty,
                UserHandle      = entry.Strings.Get(KeyUserHandle)?.ReadString() ?? string.Empty,
                UserName        = entry.Strings.Get(KeyUserName)?.ReadString() ?? string.Empty,
                UserDisplayName = entry.Strings.Get(KeyUserDisplay)?.ReadString() ?? string.Empty,
                PrivateKeyPkcs8 = entry.Strings.Get(KeyPrivateKey)?.ReadString() ?? string.Empty,
                AlgId           = int.TryParse(entry.CustomData.Get(KeyAlgId), out var alg) ? alg : -7,
                PublicKeyCose   = entry.Binaries.Get(BinPublicKey)?.ReadData() ?? Array.Empty<byte>(),
            };
    }
}
