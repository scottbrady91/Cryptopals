using System;
using System.Collections.Generic;
using System.Linq;

namespace Cryptopals
{
    public static class ByteArrayExtensions
    {
        public static string ToBinaryString(this byte[] bytes)
        {
            List<string> binaryOctets = 
                bytes.Select(x => Convert.ToString(x, 2) // get 1's & 0's
                     .PadLeft(8, '0')) // ensure always 8 chars longs & 0's on left
                    .ToList();

            return binaryOctets.Aggregate(string.Empty, 
                (current, currentBit) => current + currentBit);
        }

        public static byte[,] ToBlock(this byte[] bytes)
        {
            var block = new byte[4,4];

            var x = 0;
            var y = 0;

            for (int i = 0; i < bytes.Length; i++)
            {
                block[x, y] = bytes[i];
                y++;

                if (y == 4)
                {
                    y = 0;
                    x++;
                }
            }

            return block;
        }
    }
}