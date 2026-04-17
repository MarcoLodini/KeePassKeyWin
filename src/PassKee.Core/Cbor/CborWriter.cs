using System;
using System.Collections.Generic;
using System.IO;

namespace PassKee.Core.Cbor
{
    /// <summary>
    /// Minimal CTAP2-canonical CBOR encoder (RFC 8949 §4.2.1 + CTAP 2.1 §6).
    /// Rules:
    ///   - Shortest possible lengths (no padding).
    ///   - Definite-length items only.
    ///   - Map keys sorted by bytewise-lexicographic order of their encoded form.
    /// Only the major types required for COSE_Key and authData are implemented.
    /// </summary>
    public sealed class CborWriter
    {
        private readonly MemoryStream _buf = new MemoryStream();

        public void WriteUnsignedInt(ulong value)
        {
            WriteTypeAndValue(0, value);
        }

        public void WriteNegativeInt(long value)
        {
            // CBOR negative: major type 1, encoded value = -1 - value.
            if (value >= 0)
                throw new ArgumentOutOfRangeException(nameof(value), "Value must be negative.");
            WriteTypeAndValue(1, (ulong)(-1 - value));
        }

        public void WriteByteString(byte[] bytes)
        {
            WriteTypeAndValue(2, (ulong)bytes.Length);
            _buf.Write(bytes, 0, bytes.Length);
        }

        public void WriteTextString(string text)
        {
            var utf8 = System.Text.Encoding.UTF8.GetBytes(text);
            WriteTypeAndValue(3, (ulong)utf8.Length);
            _buf.Write(utf8, 0, utf8.Length);
        }

        /// <summary>
        /// Writes a definite-length array header. Caller must write exactly <paramref name="count"/> items after.
        /// </summary>
        public void WriteArrayHeader(int count)
        {
            WriteTypeAndValue(4, (ulong)count);
        }

        /// <summary>
        /// Writes a CTAP2-canonical map. Entries are sorted by bytewise-lex of key encoding.
        /// Each entry is a pair of pre-encoded CBOR byte arrays.
        /// </summary>
        public void WriteMap(IEnumerable<(byte[] key, byte[] value)> entries)
        {
            var pairs = new List<(byte[] key, byte[] value)>(entries);
            pairs.Sort((a, b) => BytewiseLexCompare(a.key, b.key));

            WriteTypeAndValue(5, (ulong)pairs.Count);
            foreach (var (k, v) in pairs)
            {
                _buf.Write(k, 0, k.Length);
                _buf.Write(v, 0, v.Length);
            }
        }

        /// <summary>Returns the encoded bytes.</summary>
        public byte[] Encode() => _buf.ToArray();

        // CBOR major type + argument encoding (always shortest form).
        private void WriteTypeAndValue(byte majorType, ulong value)
        {
            byte mt = (byte)(majorType << 5);
            if (value <= 23)
            {
                _buf.WriteByte((byte)(mt | (byte)value));
            }
            else if (value <= 0xFF)
            {
                _buf.WriteByte((byte)(mt | 24));
                _buf.WriteByte((byte)value);
            }
            else if (value <= 0xFFFF)
            {
                _buf.WriteByte((byte)(mt | 25));
                _buf.WriteByte((byte)(value >> 8));
                _buf.WriteByte((byte)value);
            }
            else if (value <= 0xFFFFFFFF)
            {
                _buf.WriteByte((byte)(mt | 26));
                _buf.WriteByte((byte)(value >> 24));
                _buf.WriteByte((byte)(value >> 16));
                _buf.WriteByte((byte)(value >> 8));
                _buf.WriteByte((byte)value);
            }
            else
            {
                _buf.WriteByte((byte)(mt | 27));
                for (int shift = 56; shift >= 0; shift -= 8)
                    _buf.WriteByte((byte)(value >> shift));
            }
        }

        private static int BytewiseLexCompare(byte[] a, byte[] b)
        {
            int len = Math.Min(a.Length, b.Length);
            for (int i = 0; i < len; i++)
            {
                if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
            }
            return a.Length.CompareTo(b.Length);
        }
    }
}
