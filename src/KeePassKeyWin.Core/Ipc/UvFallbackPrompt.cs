using System;

namespace KeePassKeyWin.Core.Ipc
{
    /// <summary>
    /// Asks the user once whether to proceed when Windows used the legacy v1 UV
    /// path (no caller-supplied buffer for signature verification). The user's
    /// decision is cached for the lifetime of this object — subsequent calls
    /// return the cached value without re-prompting.
    /// </summary>
    public sealed class UvFallbackPrompt
    {
        private readonly Func<bool> _ask;
        private readonly object _lock = new object();
        private bool _decided;
        private bool _decision;

        public UvFallbackPrompt(Func<bool> ask) { _ask = ask ?? throw new ArgumentNullException(nameof(ask)); }

        public bool ShouldProceed()
        {
            lock (_lock)
            {
                if (_decided) return _decision;
                // _ask() MUST be called inside the lock — concurrent v1 ops must
                // block on the first decision rather than double-prompt.
                _decision = _ask();
                _decided = true;
                return _decision;
            }
        }

        // Test-only — explicitly reset the latch.
        internal void ResetForTesting()
        {
            lock (_lock) { _decided = false; _decision = false; }
        }
    }
}
