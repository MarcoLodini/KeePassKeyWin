using System;
using System.Text;

namespace PassKee.Core.Cbor
{
    /// <summary>
    /// Minimal CTAP2 CBOR decoder (RFC 8949 §3).
    ///
    /// Supports only the major types required for CTAP2 MakeCredential requests:
    ///   0 = unsigned integer
    ///   1 = negative integer
    ///   2 = byte string
    ///   3 = text string
    ///   4 = array
    ///   5 = map
    ///
    /// Rejects everything CTAP2 forbids:
    ///   - Indefinite-length items (additional-info = 31)
    ///   - Reserved additional-info values (28, 29, 30)
    ///   - Major type 6 (tags)
    ///   - Major type 7 (floats, simple values, break)
    ///
    /// All public methods throw <see cref="CborReaderException"/> on malformed input.
    /// Does NOT require canonical key ordering on read; CTAP2 mandates canonical output only.
    /// </summary>
    public sealed class CborReader
    {
        private readonly byte[] _buf;
        private int _pos;

        /// <summary>Current read position (zero-based byte offset).</summary>
        public int Position => _pos;

        /// <summary>True when all bytes have been consumed.</summary>
        public bool IsAtEnd => _pos >= _buf.Length;

        public CborReader(byte[] data)
        {
            _buf = data ?? throw new ArgumentNullException(nameof(data));
            _pos = 0;
        }

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>Peeks the CBOR major type (0–7) of the next item without consuming any bytes.</summary>
        public int PeekMajorType()
        {
            EnsureAvailable(1);
            return _buf[_pos] >> 5;
        }

        /// <summary>Reads an unsigned integer (major type 0).</summary>
        public ulong ReadUnsignedInt()
        {
            var (mt, value) = ReadInitialByte();
            if (mt != 0)
                throw new CborReaderException($"Expected unsigned integer (major type 0), got major type {mt} at offset {_pos - 1}.");
            return value;
        }

        /// <summary>
        /// Reads a negative integer (major type 1).
        /// Returns the decoded value (always negative, e.g. -7 for COSE ES256).
        /// </summary>
        public long ReadNegativeInt()
        {
            var (mt, value) = ReadInitialByte();
            if (mt != 1)
                throw new CborReaderException($"Expected negative integer (major type 1), got major type {mt} at offset {_pos - 1}.");
            // CBOR negative: -1 - encoded_value
            if (value > (ulong)long.MaxValue)
                throw new CborReaderException($"Negative integer out of Int64 range at offset {_pos}.");
            return -1L - (long)value;
        }

        /// <summary>Reads a byte string (major type 2) and returns its content.</summary>
        public byte[] ReadByteString()
        {
            var (mt, length) = ReadInitialByte();
            if (mt != 2)
                throw new CborReaderException($"Expected byte string (major type 2), got major type {mt} at offset {_pos - 1}.");
            return ReadBytes(length);
        }

        /// <summary>Reads a text string (major type 3) and returns its UTF-8 decoded content.</summary>
        public string ReadTextString()
        {
            var (mt, length) = ReadInitialByte();
            if (mt != 3)
                throw new CborReaderException($"Expected text string (major type 3), got major type {mt} at offset {_pos - 1}.");
            var bytes = ReadBytes(length);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Reads an array header (major type 4) and returns the item count.
        /// Caller must then read exactly that many items.
        /// </summary>
        public int ReadArrayHeader()
        {
            var (mt, count) = ReadInitialByte();
            if (mt != 4)
                throw new CborReaderException($"Expected array header (major type 4), got major type {mt} at offset {_pos - 1}.");
            if (count > int.MaxValue)
                throw new CborReaderException($"Array count {count} exceeds Int32.MaxValue at offset {_pos}.");
            return (int)count;
        }

        /// <summary>
        /// Reads a map header (major type 5) and returns the pair count.
        /// Caller must then read exactly that many key-value pairs.
        /// </summary>
        public int ReadMapHeader()
        {
            var (mt, count) = ReadInitialByte();
            if (mt != 5)
                throw new CborReaderException($"Expected map header (major type 5), got major type {mt} at offset {_pos - 1}.");
            if (count > int.MaxValue)
                throw new CborReaderException($"Map pair count {count} exceeds Int32.MaxValue at offset {_pos}.");
            return (int)count;
        }

        /// <summary>
        /// Reads a CBOR simple value <c>true</c> (0xF5) or <c>false</c> (0xF4).
        /// Required by CTAP 2.1 §6.2 GetAssertion for the <c>options</c> map (up/uv).
        ///
        /// This method is the ONLY typed reader that admits a major-type-7 initial byte.
        /// All other typed readers keep rejecting MT7 — they can't return a bool anyway,
        /// and tolerating MT7 broadly would expand attack surface for no benefit.
        /// </summary>
        public bool ReadBool()
        {
            EnsureAvailable(1);
            byte b = _buf[_pos];
            if (b == 0xF5) { _pos++; return true; }
            if (b == 0xF4) { _pos++; return false; }
            throw new CborReaderException(
                $"Expected CBOR bool (0xF4/0xF5), got 0x{b:X2} at offset {_pos}.");
        }

        /// <summary>
        /// Skips the next complete CBOR item (any type), including all nested content.
        /// Used to consume unknown/ignored keys in a map.
        /// </summary>
        public void SkipValue()
        {
            EnsureAvailable(1);
            int mt = _buf[_pos] >> 5;
            int ai = _buf[_pos] & 0x1F;

            // Reject reserved/forbidden additional-info values.
            ValidateAdditionalInfo(ai);

            switch (mt)
            {
                case 0:
                case 1:
                    // Integer: just consume the initial byte + argument.
                    ReadInitialByte();
                    break;

                case 2:
                case 3:
                    // Byte/text string: read header then skip content bytes.
                {
                    var (_, length) = ReadInitialByte();
                    SkipBytes(length);
                    break;
                }

                case 4:
                    // Array: read header then skip each element.
                {
                    var (_, count) = ReadInitialByte();
                    for (ulong i = 0; i < count; i++)
                        SkipValue();
                    break;
                }

                case 5:
                    // Map: read header then skip each key-value pair.
                {
                    var (_, count) = ReadInitialByte();
                    for (ulong i = 0; i < count; i++)
                    {
                        SkipValue(); // key
                        SkipValue(); // value
                    }
                    break;
                }

                case 7:
                    // Major type 7 carries CBOR simple values and floats.
                    // CTAP2 uses it only for the 1-byte simple values
                    // false (0xf4), true (0xf5), null (0xf6), undefined
                    // (0xf7) — notably in the `options` map's rk/uv/up
                    // booleans in authenticatorMakeCredential (CTAP 2.1
                    // §6.1.1 key 7). Typed reads (ReadUnsignedInt et al)
                    // keep rejecting MT7 because those readers can't
                    // return a bool anyway; SkipValue is the only
                    // tolerance point needed for now.
                    //
                    // AI 24 (1-byte extension simple value), 25-27 (half
                    // / single / double float) are rejected — CTAP2
                    // doesn't use them and admitting them expands attack
                    // surface with no benefit. AI 28-31 were already
                    // rejected by ValidateAdditionalInfo above.
                    if (ai >= 20 && ai <= 23)
                    {
                        _pos++; // consume the single header byte; no payload
                        break;
                    }
                    throw new CborReaderException(
                        $"CBOR major type 7 with additional-info {ai} not supported at offset {_pos}.");

                default:
                    // Major type 6 (tags) — not used by CTAP2.
                    throw new CborReaderException($"Unsupported major type {mt} at offset {_pos}.");
            }
        }

        // ── Internal helpers ──────────────────────────────────────────────────

        /// <summary>
        /// Reads and decodes the initial byte + argument of the next CBOR item.
        /// Returns (majorType, argumentValue). Advances position past the header.
        /// </summary>
        private (int majorType, ulong value) ReadInitialByte()
        {
            EnsureAvailable(1);
            byte initial = _buf[_pos++];
            int mt = initial >> 5;
            int ai = initial & 0x1F;

            // Major types 6 (tag) and 7 (float/simple) are forbidden.
            if (mt == 6)
                throw new CborReaderException($"CBOR tags (major type 6) are not supported at offset {_pos - 1}.");
            if (mt == 7)
                throw new CborReaderException($"CBOR floats/simple values (major type 7) are not supported at offset {_pos - 1}.");

            ValidateAdditionalInfo(ai);

            ulong value;
            if (ai <= 23)
            {
                value = (ulong)ai;
            }
            else if (ai == 24)
            {
                EnsureAvailable(1);
                value = _buf[_pos++];
            }
            else if (ai == 25)
            {
                EnsureAvailable(2);
                value = ((ulong)_buf[_pos] << 8) | _buf[_pos + 1];
                _pos += 2;
            }
            else if (ai == 26)
            {
                EnsureAvailable(4);
                value = ((ulong)_buf[_pos] << 24) | ((ulong)_buf[_pos + 1] << 16)
                      | ((ulong)_buf[_pos + 2] << 8) | _buf[_pos + 3];
                _pos += 4;
            }
            else // ai == 27
            {
                EnsureAvailable(8);
                value = ((ulong)_buf[_pos]     << 56) | ((ulong)_buf[_pos + 1] << 48)
                      | ((ulong)_buf[_pos + 2] << 40) | ((ulong)_buf[_pos + 3] << 32)
                      | ((ulong)_buf[_pos + 4] << 24) | ((ulong)_buf[_pos + 5] << 16)
                      | ((ulong)_buf[_pos + 6] <<  8) | _buf[_pos + 7];
                _pos += 8;
            }

            return (mt, value);
        }

        /// <summary>
        /// Reads <paramref name="length"/> bytes and returns them.
        /// Guards against length-bomb: verifies bytes are available before allocating.
        /// </summary>
        private byte[] ReadBytes(ulong length)
        {
            // Fast-fail before allocation: check against remaining buffer.
            if (length > (ulong)(_buf.Length - _pos))
                throw new CborReaderException(
                    $"Byte/text string claims length {length} but only {_buf.Length - _pos} bytes remain at offset {_pos}.");
            // Additionally cap at Int32.MaxValue for array allocation safety.
            if (length > int.MaxValue)
                throw new CborReaderException($"Byte/text string length {length} exceeds Int32.MaxValue.");

            var result = new byte[(int)length];
            Array.Copy(_buf, _pos, result, 0, (int)length);
            _pos += (int)length;
            return result;
        }

        /// <summary>Skips <paramref name="length"/> bytes without allocating.</summary>
        private void SkipBytes(ulong length)
        {
            if (length > (ulong)(_buf.Length - _pos))
                throw new CborReaderException(
                    $"Byte/text string claims length {length} but only {_buf.Length - _pos} bytes remain at offset {_pos}.");
            if (length > int.MaxValue)
                throw new CborReaderException($"Byte/text string length {length} exceeds Int32.MaxValue.");
            _pos += (int)length;
        }

        private void EnsureAvailable(int count)
        {
            if (_pos + count > _buf.Length)
                throw new CborReaderException(
                    $"Unexpected end of CBOR input at offset {_pos}: need {count} more byte(s), {_buf.Length - _pos} available.");
        }

        /// <summary>
        /// Rejects reserved additional-info values (28, 29, 30) and indefinite-length (31).
        /// Call this from both ReadInitialByte and SkipValue (before the type-dispatch switch).
        /// </summary>
        private static void ValidateAdditionalInfo(int ai)
        {
            if (ai == 31)
                throw new CborReaderException("Indefinite-length CBOR items are not supported (CTAP2 §6 forbids them).");
            if (ai >= 28 && ai <= 30)
                throw new CborReaderException($"Reserved CBOR additional-info value {ai} is not supported.");
        }
    }

    /// <summary>Thrown by <see cref="CborReader"/> on any malformed or unsupported CBOR input.</summary>
    public sealed class CborReaderException : Exception
    {
        public CborReaderException(string message) : base(message) { }
        public CborReaderException(string message, Exception inner) : base(message, inner) { }
    }
}
