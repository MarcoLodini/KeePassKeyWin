using System;

namespace PassKee.Core
{
    /// <summary>
    /// Base64URL encoding/decoding per RFC 4648 §5 (no padding, + → -, / → _).
    /// </summary>
    internal static class Base64Url
    {
        internal static string Encode(byte[] data)
            => Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

        internal static byte[] Decode(string s)
        {
            var padded = s.Replace('-', '+').Replace('_', '/');
            switch (padded.Length % 4)
            {
                case 2: padded += "=="; break;
                case 3: padded += "=";  break;
            }
            return Convert.FromBase64String(padded);
        }
    }
}
