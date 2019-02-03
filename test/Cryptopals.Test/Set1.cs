using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test
{
    public class Set1
    {
        [Fact]
        public void Challenge1() // base64
        {
            const string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            const string expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            Base64.EncodeHex(hex).Should().Be(expected);
        }

        [Fact]
        public void Challenge2() // XOR
        {
            const string hex1 = "1c0111001f010100061a024b53535009181c";
            const string hex2 = "686974207468652062756c6c277320657965";
            const string expected = "746865206b696420646f6e277420706c6179";

            Xor.HexStrings(hex1, hex2).Should().Be(expected);
        }

        [Fact]
        public void Challenge3() // single-byte XOR brute force
        {
            const string cipherText = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

            // brute force each byte
            var plaintextValues = Xor.BruteForceSingleByte(cipherText);

            // figure out if a result is plaintext english
            // etaoin shrdlu cmfwyp vbgkjq xz
            string plainText = null;
            double currentHighestScore = 0;

            foreach (var attempt in plaintextValues)
            {
                var rating = LetterAnalyzer.EnglishRating(attempt.Value);
                if (currentHighestScore < rating)
                {
                    plainText = attempt.Value;
                    currentHighestScore = rating;
                }
            }

            plainText.Should().Be("Cooking MC's like a pound of bacon");
        }

        [Fact]
        public void Challenge4() // find single-byte XOR ciphertext & brute force
        {
            var cipherTexts = File.ReadAllLines("TestData/Set1/4.txt");
            
            string xoredCipherText = null;
            string plainTextValue = null;
            double currentHighestScore = 0;

            foreach (var cipherText in cipherTexts.ToList())
            {
                var plaintextValues = Xor.BruteForceSingleByte(cipherText);
                
                foreach (var attempt in plaintextValues)
                {
                    var rating = LetterAnalyzer.EnglishRating(attempt.Value);
                    if (currentHighestScore < rating)
                    {
                        xoredCipherText = cipherText;
                        plainTextValue = attempt.Value;
                        currentHighestScore = rating;
                    }
                }
            }

            xoredCipherText.Should().Be("7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f");
            plainTextValue.Should().Be("Now that the party is jumping\n");
        }

        [Fact]
        public void Challenge5() // repeating-key XOR 
        {
            const string plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            const string key = "ICE";

            const string expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

            var textAsBytes = Encoding.UTF8.GetBytes(plaintext);
            var textAsHex = Hex.BytesToString(textAsBytes);

            var keyAsBytes = Encoding.UTF8.GetBytes(key);
            var keyAsHex = Hex.BytesToString(keyAsBytes);

            var expandedKey = Xor.ExpandKey(textAsHex, keyAsHex);
            var cipherText = Xor.HexStrings(textAsHex, expandedKey);

            cipherText.Should().Be(expected);
        }

        [Fact]
        public void Challenge6() // Break repeating-key XOR
        {
            var encodedCipherText = File.ReadAllLines("TestData/Set1/6.txt")
                .Aggregate(string.Empty, (s, s1) => s + s1);

            var cipherText = Base64.DecodeBytes(encodedCipherText);

            var keySizeResults = new Dictionary<int, int>();

            // 1. "Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40."
            for (var keySize = 2; keySize <= 40; keySize++)
            {
                // 2. For hamming distance tests see Funcationlity\StringExtensionTests.cs
                // 3. "For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them.
                // Normalize this result by dividing by KEYSIZE."
                var firstKeySizeBytes = cipherText.Take(keySize);
                var secondKeySizeBytes = cipherText.Skip(keySize).Take(keySize);

                var hammingDistance = firstKeySizeBytes.GetHammingDistance(secondKeySizeBytes);
                var normalizedDistance = hammingDistance / keySize; // currently just using the first couple of blocks, maybe check the rest for a better average?

                keySizeResults.Add(keySize, normalizedDistance);
            }

            // 4. "The KEYSIZE with the smallest normalized edit distance is probably the key.
            // You could proceed perhaps with the smallest 2-3 KEYSIZE values.
            // Or take 4 KEYSIZE blocks instead of 2 and average the distances."
            var orderedResults = keySizeResults.OrderBy(x => x.Value);

            foreach ((int keySize, int _) in orderedResults)
            {
                // 5. "Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length."
                var blocksOfKeySize = cipherText.CreateMatrix(keySize);

                // 6. "Now transpose the blocks: make a block that is the first byte of every block,
                // and a block that is the second byte of every block, and so on."
                var transposedBlocks = blocksOfKeySize.Transpose();

                // 7. "Solve each block as if it was single-character XOR. You already have code to do this."
                var bruteForceResults = transposedBlocks
                    .Select(x => Xor.BruteForceSingleByte(Hex.BytesToString(x)))
                    .ToList();

                // 8. "For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
                // XOR key byte for that block. Put them together and you have the key."

                string fullKey = string.Empty;

                foreach (var result in bruteForceResults)
                {
                    string key = null;
                    string plaintext = null;
                    double currentHighestScore = 0;

                    foreach (var attempt in result)
                    {
                        var rating = LetterAnalyzer.EnglishRating(attempt.Value);
                        if (currentHighestScore < rating)
                        {
                            key = attempt.Key;
                            plaintext = attempt.Value;
                            currentHighestScore = rating;
                        }
                    }

                    fullKey += key;
                }

                var parsedKey = Encoding.ASCII.GetString(Hex.StringToBytes(fullKey));

                var expandedKey = Xor.ExpandKey(Hex.BytesToString(cipherText), fullKey);
                var bytes = Xor.ByteArrays(cipherText, Hex.StringToBytes(expandedKey));
                var s = Encoding.ASCII.GetString(bytes);
            }



            Assert.False(true); // TODO
        }

        [Fact]
        public void Challenge7() // AES in ECB mode (AES-128-ECB)
        {
            var key = "YELLOW SUBMARINE";

            // text must be processed in blocks
            // (usually 64 (2^6) or 128 (2^7) bits - a compromise between ciphertext length and memory footprint)
            // 128 or longer preferred due to being more efficient on modern CPUs & more secure (longer cipher text?)
            // encryption is performed in rounds (repeated steps) and should use a different key per round

            // AES: blocks of 128 bits, key of 128, 192, or 256 bits (128 most common, difference between 128 & 256 is unnecessary for most applicationss)
            // manipulates 16 bytes as a two dimensional array of bytes
            // performs rounds of SPN (10 for 128-bit keys, 12 for 192, 14 for 256)

            // ECB (Electronic Codebook) mode processes each block independently
            // Simple but insecure - DO NOT USE - you will get identical blocks

            // 1. Key Expansion (derive round keys from cipher key using Rijndael's key schedule)
            

            // 2. AddRoundKey: "XORs a round key to the internal state"

            // 3. REPEAT Rounds
            
                // 1. SubBytes: "Replaces each bytes with another byte according to an S-box" - Substitution

                // 2. ShiftRows: "Shifts the i-th row of i positions, for i ranging from 0 to 3" - Permutation

                // 3. MixColumns: "Applies the same linear transformation to each of the 4 columns of the state"  - Permutation

                // 4. AddRoundKey

            // 4. Final round
                // 1. SubBytes
                // 2. ShiftRows
                // 3. AddRoundKey

            Assert.False(true); // TODO
        }
    }
}
