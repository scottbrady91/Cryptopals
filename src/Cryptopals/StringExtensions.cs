using System;
using System.Linq;
using System.Text;

namespace Cryptopals
{
    public static class StringExtensions
    {
        public static int GetHammingDistance(this string x, string y)
        {
            if (x.Length != y.Length) throw new ArgumentException("values must be same length");

            return Encoding.ASCII.GetBytes(x).GetHammingDistance(Encoding.ASCII.GetBytes(y));
        }
    }
}