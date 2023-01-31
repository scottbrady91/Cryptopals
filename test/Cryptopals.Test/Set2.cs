using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Cryptopals.Test;

public class Set2
{
    private readonly ITestOutputHelper testOutputHelper;

    public Set2(ITestOutputHelper testOutputHelper)
    {
        this.testOutputHelper = testOutputHelper;
    }

    [Fact]
    public void Challenge9() // Implement PKCS#7 padding
    {
        const string block = "YELLOW SUBMARINE";
        const string expectedPaddedBlock = "YELLOW SUBMARINE\x04\x04\x04\x04"; // padded to 20 bytes

        var paddedBytes = Pkcs7.Pad(Encoding.ASCII.GetBytes(block), 20);

        Encoding.ASCII.GetString(paddedBytes).Should().Be(expectedPaddedBlock);
    }

    [Fact]
    public void Challenge10() // Implement CBC mode
    {
        const string key = "YELLOW SUBMARINE";
        var ciphertext = Convert.FromBase64String(File.ReadAllText("TestData/Set2/10.txt"));

        var challengePlaintext = AesCustom.Create(Encoding.ASCII.GetBytes(key)).DecryptCbc(ciphertext, new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

        const string expectedChallengePlaintext = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
        challengePlaintext.Should().BeEquivalentTo(Encoding.ASCII.GetBytes(expectedChallengePlaintext));
    }

    [Fact]
    public void Challenge11() // ECB/CBC detection oracle
    {
        var isEcb = AesCustom.DetectEcb(x => EncryptionOracle(x).ToArray());

        testOutputHelper.WriteLine(isEcb ? "ECB mode detected!" : "CBC mode detected");
    }

    [Fact]
    public void Challenge12()
    {
        // discover block size of cipher (call oracle with increasing large plaintext until ciphertext size increases)
        var testBlock = new List<byte>();
        testBlock.Add(0);
        var initialLength = EcbEncryptionOracle(testBlock.ToArray()).Length;
        var newLength = initialLength;
        
        while(initialLength == newLength)
        {
            testBlock.Add(0);
            newLength = EcbEncryptionOracle(testBlock.ToArray()).Length;
        }

        var blockSize = newLength - initialLength;
        blockSize.Should().Be(16); // expect 128-bit

        // detect ECB
        AesCustom.DetectEcb(x => EcbEncryptionOracle(x).ToArray()).Should().BeTrue();
        
        // get length of ciphertext
        var ciphertextLength = EcbEncryptionOracle(Array.Empty<byte>()).Length;

        // brute force
        var plaintext = new List<byte>();
        //plaintext.AddRange(BruteForceBlock(x => EcbEncryptionOracle(x).ToArray(), Array.Empty<byte>(), blockSize, 1));

        // Span<byte> bruteForceBytes = new byte[blockSize];
        // for (int j = 0; j < blockSize; j++)
        // {
        //     // isolate a byte of the unknown value
        //     var blockWithIsolatedByte = EcbEncryptionOracle(new byte[blockSize - (j + 1)]).Slice(0, 16);
        //     
        //     for (var i = 0; i < 256; i++)
        //     {
        //         bruteForceBytes[^1] = (byte)i;
        //         var bruteForcedCiphertext = EcbEncryptionOracle(bruteForceBytes.ToArray()).Slice(0, 16);
        //
        //         if (bruteForcedCiphertext.SequenceEqual(blockWithIsolatedByte.ToArray()))
        //         {
        //             if (j == blockSize - 1)
        //             {
        //                 Array.Copy(bruteForceBytes.ToArray(), 0, plaintext, 0, bruteForceBytes.Length);
        //             }
        //             else
        //             {
        //                 var temp = new byte[blockSize];
        //                 Array.Copy(bruteForceBytes.ToArray(), 1, temp, 0, bruteForceBytes.Length - 1);
        //                 bruteForceBytes = temp;
        //             }
        //             
        //             
        //             break;
        //         }
        //     }
        // }
        
        Span<byte> unknownValue = Base64.DecodeBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        /*unknownValue.Slice(0, blockSize).SequenceEqual(plaintext.ToArray()).Should().BeTrue();
        
        plaintext.AddRange(BruteForceBlock(x => EcbEncryptionOracle(x).ToArray(), plaintext.ToArray(), blockSize, 2));
        unknownValue.Slice(0, blockSize * 2).SequenceEqual(plaintext.ToArray()).Should().BeTrue();*/


        for (int i = 0; i < ciphertextLength / blockSize; i++)
        {
            plaintext.AddRange(BruteForceBlock(x => EcbEncryptionOracle(x).ToArray(), plaintext.ToArray(), blockSize, i + 1));
        }

        unknownValue.SequenceEqual(plaintext.ToArray());
    }

    
    /// <summary>
    /// Currently brute forces first block only
    /// </summary>
    private byte[] BruteForceBlock(Func<byte[], byte[]> oracle, byte[] knownBytes, int blockSize, int blockNumber)
    {
        if (knownBytes.Length % blockSize != 0) throw new Exception("Known bytes must be in correct block sizes");
        
        List<byte> bruteForcedBytes = new List<byte>();
        
        for (var blockPosition = 0; blockPosition < blockSize; blockPosition++)
        {
            // isolate a byte of the unknown value (a ciphertext where only the last byte of the first block is unknown to us)
            byte[] blockWithIsolatedByte;
            blockWithIsolatedByte = oracle(new byte[blockSize - (blockPosition + 1)]).Take(blockSize * blockNumber).ToArray();
            
            // brute force the isolated byte
            byte[] bfb = new byte[blockSize * blockNumber];
            if (knownBytes.Any()) Array.Copy(knownBytes, 0, bfb, blockSize - blockPosition - 1, knownBytes.Length);
            Array.Copy(bruteForcedBytes.ToArray(), 0, bfb, blockSize - blockPosition + knownBytes.Length - 1, bruteForcedBytes.Count);
            
            
            for (var i = 0; i < 256; i++)
            {
                bfb[^1] = (byte)i;
                var bruteForcedCiphertext = oracle(bfb.ToArray()).Take(blockSize * blockNumber);

                if (bruteForcedCiphertext.SequenceEqual(blockWithIsolatedByte))
                {
                    bruteForcedBytes.Add((byte)i);
                    
                    if (blockPosition == (blockSize) - 1)
                    {
                        return Pkcs7.Unpad(bruteForcedBytes.ToArray()).ToArray();
                    }
                    
                    break;
                }
            }
        }

        throw new NotSupportedException("it broke");
    }

    private static byte[] GenerateKey(int length)
    {
        var key = new byte[length];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static Span<byte> EncryptionOracle(byte[] plaintext)
    {
        var key = GenerateKey(16);
        var aes = AesCustom.Create(key);

        var prependBytes = new byte[RandomNumberGenerator.GetInt32(5, 10)]; RandomNumberGenerator.Fill(prependBytes);
        var appendBytes = new byte[RandomNumberGenerator.GetInt32(5, 10)]; RandomNumberGenerator.Fill(appendBytes);

        var challengePlaintext = new byte[plaintext.Length + prependBytes.Length + appendBytes.Length];
        Array.Copy(prependBytes, 0, challengePlaintext, 0, prependBytes.Length);
        Array.Copy(plaintext, 0, challengePlaintext, prependBytes.Length, plaintext.Length);
        Array.Copy(appendBytes, 0, challengePlaintext, prependBytes.Length + plaintext.Length, appendBytes.Length);
        
        if (RandomNumberGenerator.GetInt32(2) == 0)
        {
            var iv = new byte[16];
            RandomNumberGenerator.Fill(iv);
            return aes.EncryptCbc(challengePlaintext, iv);
        }

        return aes.EncryptEcb(challengePlaintext);
    }

    private static readonly byte[] EcbEncryptionOracleKey = GenerateKey(16);
    private static Span<byte> EcbEncryptionOracle(byte[] plaintext)
    {
        var aes = AesCustom.Create(EcbEncryptionOracleKey);
        var unknownValue = Base64.DecodeBytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

        var challengePlaintext = new byte[plaintext.Length + unknownValue.Length];
        Array.Copy(plaintext, 0, challengePlaintext, 0, plaintext.Length);
        Array.Copy(unknownValue, 0, challengePlaintext, plaintext.Length, unknownValue.Length);

        return aes.EncryptEcb(challengePlaintext);
    }
}