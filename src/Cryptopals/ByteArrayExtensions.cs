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

        public static int GetHammingDistance(this IEnumerable<byte> x, IEnumerable<byte> y)
        {
            return GetHammingDistance(x.ToArray(), y.ToArray());
        }

        public static int GetHammingDistance(this byte[] x, byte[] y)
        {
            if (x.Length != y.Length) throw new ArgumentException("values must be same length");

            var distance = 0;

            for (var i = 0; i < x.Length; i++)
            {
                var value = (int)Xor.Bytes(x[i], y[i]);

                while (value != 0)
                {
                    distance++;
                    value &= value - 1;
                }
            }

            return distance;
        }

        public static T[][] CreateMatrix<T>(this IEnumerable<T> source, int size)
        {
            var taken = 0;
            var output = new List<T[]>();
            var enumeratedSource = source.ToArray();

            while (taken < enumeratedSource.Length)
            {
                output.Add(enumeratedSource.Skip(taken).Take(size).ToArray());
                taken += size;
            }

            return output.ToArray();
        }

        public static T[][] Transpose<T>(this T[][] source)
        {
            var transposedBlocks = new List<List<T>>();

            for (var i = 0; i <= source.Length; i++)
            {
                foreach (var block in source.ToList())
                {
                    if (i < block.Length)
                    {
                        if (transposedBlocks.ElementAtOrDefault(i) == null)
                            transposedBlocks.Add(new List<T>());

                        transposedBlocks[i].Add(block[i]);
                    }
                }
            }

            return transposedBlocks.Select(x => x.ToArray()).ToArray();
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