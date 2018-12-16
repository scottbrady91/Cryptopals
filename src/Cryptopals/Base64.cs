using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{

    // ASCII to "radix-64" representation
    // each digit is 6 bytes of data (therefore 3 bytes (24 bytes) == 4 digit Base64 string)
    // e.g. Man -> ASCI: 77, 97, 110 -> Binary (octet): 01001101, 01100001, 01101110 -> Binary (sextet): 19, 22, 5, 46 -> Base64: TWFu
    public static class Base64
    {
        public static string EncodeString(string value)
        {
            var bytes = Encoding.ASCII.GetBytes(value);
            return EncodeBytes(bytes);
        }
        
        public static string EncodeHex(string hex)
        {
            var bytes = Hex.StringToBytes(hex); // get bytes from hex string (binary octets)
            return EncodeBytes(bytes);
        }

        public static string EncodeBytes(byte[] bytes)
        {
            // to binary
            var binary = bytes.ToBinaryString();

            // to sextets
            var sextets = OctetsToSextet(binary);

            // to base64
            string base64String = null;

            foreach (var sextet in sextets)
            {
                base64String += Base64Lookup[sextet];
            }

            // padding (result must be divisible by three)
            if (bytes.Length % 3 != 0)
            {
                if (bytes.Length % 3 == 1) base64String += "=="; // if only 1 remainder, then pad to 3
                if (bytes.Length % 3 == 2) base64String += "="; // if only 2 remainder, then pad to 2
            }

            return base64String;
        }

        // take every six bits and parse
        private static List<int> OctetsToSextet(string bits)
        {
            var taken = 0;
            var sextets = new List<int>();
            
            while (taken < bits.Length)
            {
                var sextet = bits.Skip(taken).Take(6).Aggregate(string.Empty, (c, c1) => c + c1);

                if (sextet.Length != 6)
                {
                    sextet = sextet.PadRight(6, '0'); // if not 6 in length, pad right with 0's
                }
                
                sextets.Add(Convert.ToInt32(sextet, 2));
                taken += 6;
            }

            return sextets;
        }
        
        // allowedCharacters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        private static readonly char[] Base64Lookup =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };
    }
}