using System;

namespace Cryptopals
{
    public static class Hex
    {
        // hex = base16 (0-9 and A-F (or a-f))
        // each digit represents 4 bits (a nibble)
        // 0000 0000 = 00 && 1111 1111 = FF
        // prefixed by 0x in C languages (e.g. 0xFF)
        public static byte[] StringToBytes(string hex)
        {
            var hexAsBytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2)
            {
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            
            return hexAsBytes;
        }

        public static string BytesToString(byte[] bytes)
        {
            return BitConverter.ToString(bytes)
                .Replace("-", string.Empty).ToLower(); // BitConverter defaults to format of 4D-61-6e
        }
    }
}