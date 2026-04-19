using System;
using System.Collections.Generic;
using System.Globalization;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;
using KeePassKeyWin.Core.Storage;

namespace KeePassKeyWin.Plugin.Storage
{
    /// <summary>
    /// IPasskeyStore backed by a KeePass PwDatabase. Reads and writes PwEntry records
    /// in the "Passkeys" group using the storage schema defined in ARCHITECTURE.md.
    /// </summary>
    public sealed class KeePassPasskeyStore : IPasskeyStore
    {
        private const string GroupName      = "Passkeys";
        private const string KeyCredId      = "KeePassKeyWin.credentialId";
        private const string KeyRpId        = "KeePassKeyWin.rpId";
        private const string KeyRpName      = "KeePassKeyWin.rpName";
        private const string KeyUserHandle  = "KeePassKeyWin.userHandle";
        private const string KeyUserName    = "KeePassKeyWin.userName";
        private const string KeyUserDisplay = "KeePassKeyWin.userDisplayName";
        private const string KeyPrivateKey  = "KeePassKeyWin.privateKey";
        private const string KeyAlgId        = "KeePassKeyWin.algId";
        private const string KeySignCount   = "KeePassKeyWin.signCount";
        private const string KeyAaguid      = "KeePassKeyWin.aaguid";
        private const string KeyTransports  = "KeePassKeyWin.transports";
        private const string KeyFlags       = "KeePassKeyWin.flags";
        private const string KeyCreated     = "KeePassKeyWin.creationTime";
        private const string KeyLastUsed    = "KeePassKeyWin.lastUsedTime";
        private const string BinPublicKey   = "KeePassKeyWin.publicKey.cbor";

        private readonly IPluginHost _host;

        // Serialises IncrementSignCount against itself and against Add. Parallel
        // browser login flows can land concurrent GetAssertion dispatches on the
        // same KeePass database; WebAuthn L3 §6.1.1 requires a monotonic counter
        // — a lost increment manifests as a replayed signCount which RPs may
        // treat as a cloned authenticator.
        private readonly object _lock = new object();

        public KeePassPasskeyStore(IPluginHost host)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
        }

        public bool IsVaultOpen => _host.Database?.IsOpen == true;

        public void Add(PasskeyRecord record)
        {
            var group = EnsurePasskeysGroup();
            // KeePass's PwEntry has no parameterless ctor; we must request a fresh
            // UUID + creation/modification timestamps for a newly minted entry.
            var entry = new PwEntry(bCreateNewUuid: true, bSetTimes: true);

            entry.Strings.Set(KeyCredId,      new ProtectedString(false, record.CredentialId));
            entry.Strings.Set(KeyRpId,        new ProtectedString(false, record.RpId));
            entry.Strings.Set(KeyRpName,      new ProtectedString(false, record.RpName));
            entry.Strings.Set(KeyUserHandle,  new ProtectedString(false, record.UserHandle));
            entry.Strings.Set(KeyUserName,    new ProtectedString(false, record.UserName));
            entry.Strings.Set(KeyUserDisplay, new ProtectedString(false, record.UserDisplayName));
            entry.Strings.Set(KeyPrivateKey,  new ProtectedString(true, record.PrivateKeyPkcs8));
            entry.CustomData.Set(KeyAlgId,     record.AlgId.ToString());
            entry.CustomData.Set(KeySignCount, "0");
            entry.CustomData.Set(KeyAaguid,    "00000000000000000000000000000000");
            entry.CustomData.Set(KeyTransports, record.Transports);
            entry.CustomData.Set(KeyFlags,     record.Flags);
            entry.CustomData.Set(KeyCreated,   record.CreationTime.ToString("o"));
            entry.CustomData.Set(KeyLastUsed,  record.LastUsedTime.ToString("o"));
            entry.Binaries.Set(BinPublicKey,   new ProtectedBinary(false, record.PublicKeyCose));

            // KeePass entry title for human readability.
            entry.Strings.Set("Title", new ProtectedString(false,
                $"{record.RpName} / {record.UserDisplayName}"));

            group.AddEntry(entry, bTakeOwnership: true);
            _host.Database!.Save(null);

            var mw = _host.MainWindow;
            if (mw?.IsHandleCreated == true)
                mw.BeginInvoke(new Action(() =>
                    mw.UpdateUI(false, null, true, null, true, null, false)));
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
                    _host.Database!.Save(null);

                    var mw = _host.MainWindow;
                    if (mw?.IsHandleCreated == true)
                        mw.BeginInvoke(new Action(() =>
                            mw.UpdateUI(false, null, true, null, true, null, false)));

                    return true;
                }
            }
            return false;
        }

        public uint IncrementSignCount(string credentialId)
        {
            if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));

            // Lock covers find + increment + save as one atomic operation so
            // concurrent GetAssertion dispatches produce strictly monotonic values.
            lock (_lock)
            {
                var group = FindPasskeysGroup()
                    ?? throw new KeyNotFoundException(
                        $"Vault is closed or no Passkeys group exists; cannot increment signCount for {credentialId}.");

                PwEntry? target = null;
                for (uint i = 0; i < group.Entries.UCount; i++)
                {
                    var entry = group.Entries.GetAt(i);
                    var id = entry.Strings.Get(KeyCredId)?.ReadString();
                    if (string.Equals(id, credentialId, StringComparison.Ordinal))
                    {
                        target = entry;
                        break;
                    }
                }
                if (target == null)
                    throw new KeyNotFoundException($"Credential not found: {credentialId}");

                uint current = 0;
                var raw = target.CustomData.Get(KeySignCount);
                if (!string.IsNullOrEmpty(raw))
                    uint.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out current);

                if (current == uint.MaxValue)
                    throw new InvalidOperationException(
                        $"signCount overflow for credential {credentialId} (already at uint.MaxValue).");

                uint next = current + 1;
                target.CustomData.Set(KeySignCount, next.ToString(CultureInfo.InvariantCulture));
                target.Touch(bModified: true, bTouchParents: false);

                // Synchronous save: a KeePass-close-without-save would replay the
                // old counter on next login, which RPs flag as cloned authenticator
                // (WebAuthn L3 §6.1.1). Non-negotiable; see docs/ARCHITECTURE.md.
                _host.Database!.Save(null);

                var mw = _host.MainWindow;
                if (mw?.IsHandleCreated == true)
                    mw.BeginInvoke(new Action(() =>
                        mw.UpdateUI(false, null, true, null, true, null, false)));

                return next;
            }
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
                Transports      = entry.CustomData.Get(KeyTransports) ?? "internal",
                Flags           = entry.CustomData.Get(KeyFlags) ?? string.Empty,
                CreationTime    = DateTime.TryParse(entry.CustomData.Get(KeyCreated), null, DateTimeStyles.RoundtripKind, out var ct) ? ct : DateTime.MinValue,
                LastUsedTime    = DateTime.TryParse(entry.CustomData.Get(KeyLastUsed), null, DateTimeStyles.RoundtripKind, out var lu) ? lu : DateTime.MinValue,
                SignCount       = uint.TryParse(entry.CustomData.Get(KeySignCount), NumberStyles.Integer, CultureInfo.InvariantCulture, out var sc) ? sc : 0u,
            };
    }
}
