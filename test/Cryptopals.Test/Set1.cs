using System;
using FluentAssertions;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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

            byte[] cipherText = Base64.DecodeBytes(encodedCipherText);

            var keySizeResults = new Dictionary<int, int>();

            // 1. "Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40."
            for (var keySize = 2; keySize <= 40; keySize++)
            {
                // 2. For hamming distance tests see Funcationlity\StringExtensionTests.cs
                // 3. "For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them.
                // Normalize this result by dividing by KEYSIZE."

                var hammingDistance = 0;
                var numberOfHams = 0;

                for (int i = 1; i < cipherText.Length / keySize; i++)
                {
                    var firstKeySizeBytes = cipherText.Skip(keySize * (i - 1)).Take(keySize);
                    var secondKeySizeBytes = cipherText.Skip(keySize * i).Take(keySize);

                    hammingDistance += firstKeySizeBytes.GetHammingDistance(secondKeySizeBytes);
                    numberOfHams++;
                }

                var normalizedDistance = hammingDistance / numberOfHams / keySize;
                keySizeResults.Add(keySize, normalizedDistance);
            }

            // 4. "The KEYSIZE with the smallest normalized edit distance is probably the key.
            // You could proceed perhaps with the smallest 2-3 KEYSIZE values.
            // Or take 4 KEYSIZE blocks instead of 2 and average the distances."
            var orderedResults = keySizeResults.OrderBy(x => x.Value);
            var bestKeySize = orderedResults.First().Key;

            // 5. "Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length."
            var blocksOfKeySize = cipherText.CreateMatrix(bestKeySize);

            // 6. "Now transpose the blocks: make a block that is the first byte of every block,
            // and a block that is the second byte of every block, and so on."
            var transposedBlocks = blocksOfKeySize.Transpose();

            // 7. "Solve each block as if it was single-character XOR. You already have code to do this."
            var bruteForceResults = transposedBlocks
                .Select(x => Xor.BruteForceSingleByte(Hex.BytesToString(x)))
                .ToList();

            // 8. "For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
            // XOR key byte for that block. Put them together and you have the key."
            var fullKey = string.Empty;

            foreach (var result in bruteForceResults)
            {
                string key = null;
                double currentHighestScore = 0;

                foreach (var attempt in result)
                {
                    var rating = LetterAnalyzer.EnglishRating(attempt.Value);
                    if (currentHighestScore < rating)
                    {
                        key = attempt.Key;
                        currentHighestScore = rating;
                    }
                }

                fullKey += key;
            }

            var expandedKey = Xor.ExpandKey(Hex.BytesToString(cipherText), fullKey);
            var bytes = Xor.ByteArrays(cipherText, Hex.StringToBytes(expandedKey));

            var parsedKey = Encoding.UTF8.GetString(Hex.StringToBytes(fullKey));
            var plaintext = Encoding.UTF8.GetString(bytes);

            parsedKey.Should().Be("Terminator X: Bring the noise");
            plaintext.Should().Be("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");
        }

        [Fact]
        public void Challenge7() // AES in ECB mode (AES-128-ECB)
        {
            const string key = "YELLOW SUBMARINE";
            string challengeCiphertext = File.ReadAllText("TestData/Set1/7.txt");

            // using System.Security.Cryptography implementation to skip implementing AES myself...
            var aes = AesCustom.Create(Encoding.ASCII.GetBytes(key));
            var challengePlaintext = aes.DecryptEcb(Convert.FromBase64String(challengeCiphertext));

            const string expectedChallengePlaintext = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
            challengePlaintext.SequenceEqual(Encoding.ASCII.GetBytes(expectedChallengePlaintext)).Should().BeTrue();
        }

        [Fact]
        public void Challenge8() // detect ECB
        {
            var ciphertextsAsHex = File.ReadAllLines("TestData/Set1/8.txt").ToList();
            string suspectedEcbCiphertext = null;

            // "Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext."
            foreach (var ciphertextHex in ciphertextsAsHex)
            {
                var hashset = new HashSet<string>();
                var blocks = ciphertextHex.Chunk(32).Select(x => new string(x)).ToList();

                if (blocks.Any(block => !hashset.Add(block)))
                {
                    suspectedEcbCiphertext = ciphertextHex;
                }
            }

            suspectedEcbCiphertext.Should().Be("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
        }
    }
}
