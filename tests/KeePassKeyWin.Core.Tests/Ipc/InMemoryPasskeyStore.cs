using System;
using System.Collections.Generic;
using System.Linq;
using KeePassKeyWin.Core.Storage;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    /// <summary>Test double for IPasskeyStore — stores records in memory.</summary>
    internal sealed class InMemoryPasskeyStore : IPasskeyStore
    {
        private readonly Dictionary<string, PasskeyRecord> _records = new Dictionary<string, PasskeyRecord>();
        private readonly object _lock = new object();

        public bool IsVaultOpen { get; set; } = true;

        public void Add(PasskeyRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));
            lock (_lock)
            {
                _records[record.CredentialId] = record;
            }
        }

        public IReadOnlyList<PasskeyRecord> FindByRpId(string rpId)
        {
            lock (_lock) return _records.Values.Where(r => r.RpId == rpId).ToList();
        }

        public PasskeyRecord? FindById(string credentialId)
        {
            lock (_lock) return _records.TryGetValue(credentialId, out var r) ? r : null;
        }

        public bool Delete(string credentialId)
        {
            lock (_lock) return _records.Remove(credentialId);
        }

        public IReadOnlyList<PasskeyRecord> GetAll()
        {
            lock (_lock) return _records.Values.ToList();
        }

        public uint IncrementSignCount(string credentialId)
        {
            if (credentialId == null) throw new ArgumentNullException(nameof(credentialId));
            lock (_lock)
            {
                if (!_records.TryGetValue(credentialId, out var r))
                    throw new KeyNotFoundException($"Credential not found: {credentialId}");
                if (r.SignCount == uint.MaxValue)
                    throw new InvalidOperationException("signCount overflow.");
                r.SignCount++;
                return r.SignCount;
            }
        }
    }
}
