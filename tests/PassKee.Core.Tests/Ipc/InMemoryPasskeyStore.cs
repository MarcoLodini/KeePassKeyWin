using System;
using System.Collections.Generic;
using System.Linq;
using PassKee.Core.Storage;

namespace PassKee.Core.Tests.Ipc
{
    /// <summary>Test double for IPasskeyStore — stores records in memory.</summary>
    internal sealed class InMemoryPasskeyStore : IPasskeyStore
    {
        private readonly Dictionary<string, PasskeyRecord> _records = new Dictionary<string, PasskeyRecord>();

        public bool IsVaultOpen { get; set; } = true;

        public void Add(PasskeyRecord record)
        {
            if (record == null) throw new ArgumentNullException(nameof(record));
            _records[record.CredentialId] = record;
        }

        public IReadOnlyList<PasskeyRecord> FindByRpId(string rpId)
            => _records.Values.Where(r => r.RpId == rpId).ToList();

        public PasskeyRecord? FindById(string credentialId)
            => _records.TryGetValue(credentialId, out var r) ? r : null;

        public bool Delete(string credentialId)
            => _records.Remove(credentialId);

        public IReadOnlyList<PasskeyRecord> GetAll()
            => _records.Values.ToList();
    }
}
