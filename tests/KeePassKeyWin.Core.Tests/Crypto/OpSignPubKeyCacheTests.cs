using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using KeePassKeyWin.Core.Crypto;
using Xunit;

namespace KeePassKeyWin.Core.Tests.Crypto
{
    /// <summary>
    /// Unit tests for <see cref="OpSignPubKeyCache"/>.
    ///
    /// Each test resets the static cache via <see cref="OpSignPubKeyCache.ResetForTesting"/>
    /// so tests do not bleed state into each other. xUnit does not guarantee test ordering
    /// so every test that requires a clean initial state must reset first.
    /// </summary>
    public class OpSignPubKeyCacheTests
    {
        // ── Null before first set ─────────────────────────────────────────────────

        [Fact]
        public void Current_BeforeAnySet_IsNull()
        {
            OpSignPubKeyCache.ResetForTesting();

            Assert.Null(OpSignPubKeyCache.Current);
        }

        // ── Set / Current round-trip ─────────────────────────────────────────────

        [Fact]
        public void Set_ThenCurrent_ReturnsSameBytes()
        {
            OpSignPubKeyCache.ResetForTesting();

            var original = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            OpSignPubKeyCache.Set(original);

            var retrieved = OpSignPubKeyCache.Current;

            Assert.NotNull(retrieved);
            Assert.Equal(original, retrieved!.Value.ToArray());
        }

        // ── Replacement semantics ────────────────────────────────────────────────

        [Fact]
        public void Set_CalledTwice_SecondValueWins()
        {
            OpSignPubKeyCache.ResetForTesting();

            var first  = new byte[] { 0xAA, 0xBB };
            var second = new byte[] { 0xCC, 0xDD, 0xEE };

            OpSignPubKeyCache.Set(first);
            OpSignPubKeyCache.Set(second);

            var retrieved = OpSignPubKeyCache.Current;

            Assert.NotNull(retrieved);
            Assert.Equal(second, retrieved!.Value.ToArray());
        }

        // ── Defensive copy: caller mutation does not affect cache ─────────────────

        [Fact]
        public void Set_MutatingOriginalAfterSet_DoesNotAffectCache()
        {
            OpSignPubKeyCache.ResetForTesting();

            var original = new byte[] { 0x01, 0x02, 0x03 };
            OpSignPubKeyCache.Set(original);

            // Mutate the original array after Set.
            original[0] = 0xFF;

            var retrieved = OpSignPubKeyCache.Current;

            Assert.NotNull(retrieved);
            // The cache must hold 0x01, not 0xFF (defensive copy was taken).
            Assert.Equal(0x01, retrieved!.Value.Span[0]);
        }

        // ── ResetForTesting clears the cache ─────────────────────────────────────

        [Fact]
        public void ResetForTesting_ClearsCache()
        {
            OpSignPubKeyCache.Set(new byte[] { 0x42 });
            OpSignPubKeyCache.ResetForTesting();

            Assert.Null(OpSignPubKeyCache.Current);
        }

        // ── Thread-safety: concurrent Set + Current ──────────────────────────────

        [Fact]
        public void ThreadSafety_ConcurrentSetAndCurrent_NoExceptions()
        {
            OpSignPubKeyCache.ResetForTesting();

            const int threadCount = 16;
            const int iterationsPerThread = 200;
            var errors = new System.Collections.Concurrent.ConcurrentBag<Exception>();

            var barrier = new Barrier(threadCount);

            var threads = new List<Thread>();
            for (int t = 0; t < threadCount; t++)
            {
                int threadId = t;
                var thread = new Thread(() =>
                {
                    // All threads start at roughly the same time.
                    barrier.SignalAndWait();

                    try
                    {
                        for (int i = 0; i < iterationsPerThread; i++)
                        {
                            if (i % 3 == 0)
                            {
                                // Writer thread: set a new value.
                                OpSignPubKeyCache.Set(new byte[] { (byte)threadId, (byte)i });
                            }
                            else
                            {
                                // Reader thread: just read; value may be null or non-null.
                                var current = OpSignPubKeyCache.Current;
                                // No assertion on the value — we only check no exception is thrown.
                                _ = current?.ToArray();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        errors.Add(ex);
                    }
                });
                threads.Add(thread);
            }

            foreach (var t in threads) t.Start();
            foreach (var t in threads) t.Join();

            Assert.Empty(errors);
        }

        // ── Current returns a consistent snapshot ─────────────────────────────────

        [Fact]
        public void Current_ReturnedMemory_IsReadableAfterSubsequentSet()
        {
            OpSignPubKeyCache.ResetForTesting();

            var first = new byte[] { 0x01, 0x02 };
            OpSignPubKeyCache.Set(first);

            // Take a snapshot of Current.
            var snapshot = OpSignPubKeyCache.Current;
            Assert.NotNull(snapshot);

            // Now replace the cache value.
            OpSignPubKeyCache.Set(new byte[] { 0xFF });

            // The snapshot taken before the replacement must still be readable.
            Assert.Equal(first, snapshot!.Value.ToArray());
        }
    }
}
