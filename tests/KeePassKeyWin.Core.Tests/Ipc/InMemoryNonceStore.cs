using System.Collections.Generic;
using KeePassKeyWin.Core.Ipc;

namespace KeePassKeyWin.Core.Tests.Ipc
{
    // Test double: single-use nonce backed by a HashSet.
    internal sealed class InMemoryNonceStore : INonceStore
    {
        private readonly HashSet<string> _nonces = new();

        public void Add(string nonce) => _nonces.Add(nonce);

        public bool ConsumeNonce(string nonce)
        {
            return _nonces.Remove(nonce);
        }
    }
}
