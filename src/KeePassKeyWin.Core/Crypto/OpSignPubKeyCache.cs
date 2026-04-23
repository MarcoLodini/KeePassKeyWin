using System;
using System.Threading;

namespace KeePassKeyWin.Core.Crypto
{
    /// <summary>
    /// Process-lifetime cache for the Windows operation-signing public key bytes
    /// (<c>BCRYPT_PUBLIC_KEY_BLOB</c>) received from the sidecar during handshake.
    ///
    /// <para>
    /// <b>Design: static singleton.</b> Mirrors the Rust sidecar's <c>OnceLock</c>
    /// pattern: there is exactly one op-signing key per KeePass session, shared by all
    /// IPC connections. Making this an instance would require threading it through every
    /// handler — the singleton avoids that coupling.
    /// <c>InternalsVisibleTo("KeePassKeyWin.Core.Tests")</c> is already configured in
    /// the csproj; tests call <c>ResetForTesting()</c> to restore a clean slate.
    /// </para>
    ///
    /// <para>
    /// <b>Replacement policy (deliberately minimal in 5.UV.1).</b> <c>Set</c> replaces
    /// any existing value unconditionally. Whether replacement should be gated
    /// (first-wins, divergence rejection, etc.) is deferred to 5.UV.2 / 5.UV.4
    /// once the verifier is actually consumed in the critical path.
    /// </para>
    ///
    /// <para>
    /// <b>Thread-safety.</b> The backing field is a <c>byte[]?</c> reference.
    /// <c>Interlocked.Exchange</c> provides sequentially-consistent exchange on the
    /// reference, so concurrent <c>Set</c> and <c>Current</c> calls are safe without
    /// additional locking.
    /// </para>
    /// </summary>
    public static class OpSignPubKeyCache
    {
        // Backing field: volatile reference semantics via Interlocked.
        // null = not yet set; non-null = a defensive copy of the caller's bytes.
        private static byte[]? _bytes;

        /// <summary>
        /// Replace the cached pubkey bytes with <paramref name="pubKeyBlob"/>.
        /// A defensive copy is made so the caller cannot mutate the cached value.
        /// </summary>
        /// <remarks>
        /// Later sub-phases will decide whether replacement should be gated
        /// (divergence rejection, first-wins, etc.). 5.UV.1 just stores what's given.
        /// Thread-safe under concurrent calls.
        /// </remarks>
        public static void Set(ReadOnlyMemory<byte> pubKeyBlob)
        {
            // Defensive copy: callers cannot mutate the cached slice after Set returns.
            var copy = pubKeyBlob.ToArray();
            Interlocked.Exchange(ref _bytes, copy);
        }

        /// <summary>The cached pubkey bytes, or <c>null</c> if never set.</summary>
        public static ReadOnlyMemory<byte>? Current
        {
            get
            {
                // Single volatile read via Interlocked.CompareExchange(no-op) is not
                // needed here: reading a managed reference is atomic on all .NET targets.
                // We snapshot the field once so we return a consistent value.
                var snapshot = Volatile.Read(ref _bytes);
                return snapshot == null ? null : (ReadOnlyMemory<byte>?)snapshot;
            }
        }

        /// <summary>
        /// Resets the cache to the unset state.
        /// For test isolation only — relies on <c>[InternalsVisibleTo("KeePassKeyWin.Core.Tests")]</c>.
        /// Do not call from production code.
        /// </summary>
        internal static void ResetForTesting()
        {
            Interlocked.Exchange(ref _bytes, null);
        }
    }
}
