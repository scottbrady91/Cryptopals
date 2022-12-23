using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    // exclusive OR
    // https://en.wikipedia.org/wiki/XOR_gate
    public static class Xor
    {
        public static string HexStrings(string x, string y)
        {
            var xBytes = Hex.StringToBytes(x);
            var yBytes = Hex.StringToBytes(y);

            var xorData = ByteArrays(xBytes, yBytes);
            
            return Hex.BytesToString(xorData);
        }

        public static byte[] ByteArrays(Span<byte> x, Span<byte> y)
        {
            var xorData = new byte[x.Length];
            
            for (var i = 0; i < x.Length; i++)
                xorData[i] = Bytes(x[i], y[i]);
            
            return xorData;
        }

        public static byte Bytes(byte x, byte y)
        {
            return (byte) (x ^ y);
        }

        public static Dictionary<string, string> BruteForceSingleByte(string cipherText)
        {
            var outputs = new Dictionary<string, string>();
            foreach (var key in Enumerable.Range(0, 127))
            {
                var keyAsHex = Convert.ToString(key, 16);
                var expandedKey = ExpandKey(cipherText, keyAsHex);

                var outputHex = Xor.HexStrings(cipherText, expandedKey);
                var outputBytes = Hex.StringToBytes(outputHex);
                outputs.Add(keyAsHex, Encoding.ASCII.GetString(outputBytes));
            }

            return outputs;
        }

        public static string ExpandKey(string hex, string key)
        {
            var expandedKey = string.Empty;

            while (expandedKey.Length < hex.Length)
            {
                expandedKey += key;
            }

            return expandedKey;
        }
    }
}