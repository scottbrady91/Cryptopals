using System;
using System.Collections.Generic;
using System.Linq;

namespace Cryptopals
{
    public static class LetterAnalyzer
    {
        // https://crypto.stackexchange.com/a/56477/52819 (Bhattacharyya coefficient approach)
        public static double EnglishRating(string text)
        {
            var chars = text.ToUpper().GroupBy(c => c).Select(g => new {g.Key, Count = g.Count()});

            double coefficient = 0;

            foreach (var c in chars)
            {
                if (LetterScore.TryGetValue(c.Key, out var freq))
                {
                    coefficient += Math.Sqrt(freq * c.Count / text.Length);

                }
            }

            return coefficient;
        }

        // http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
        private static readonly Dictionary<char, double> LetterScore = new Dictionary<char, double>
        {
            {'E', 12.02},
            {'T', 9.10},
            {'A', 8.12},
            {'O', 7.68},
            {'I', 7.31},
            {'N', 6.95},
            {'S', 6.28},
            {'R', 6.02},
            {'H', 5.92},
            {'D', 4.32},
            {'L', 3.98},
            {'U', 2.88},
            {'C', 2.71},
            {'M', 2.61},
            {'F', 2.30},
            {'Y', 2.11},
            {'W', 2.09},
            {'G', 2.03},
            {'P', 1.82},
            {'B', 1.49},
            {'V', 1.11},
            {'K', 0.69},
            {'X', 0.17},
            {'Q', 0.11},
            {'J', 0.10},
            {'Z', 0.07}
        };
    }
}