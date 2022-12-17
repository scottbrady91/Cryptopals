using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    // ReSharper disable once InconsistentNaming
    public class AESTests
    {
        [Fact]
        public void ExpandKey_UsingDataFromMoserware()
        {
            const string key = "SOME 128 BIT KEY";

            var expandKey = new AES().GetRoundKey(Encoding.ASCII.GetBytes(key), 1);

            expandKey[0].Should().Be(0xe1);
            expandKey[1].Should().Be(0x21);
            expandKey[2].Should().Be(0x86);
            expandKey[3].Should().Be(0xf2);
            expandKey[4].Should().Be(0xc1);
            expandKey[5].Should().Be(0x10);
            expandKey[6].Should().Be(0xb4);
            expandKey[7].Should().Be(0xca);
            expandKey[8].Should().Be(0xe1);
            expandKey[9].Should().Be(0x52);
            expandKey[10].Should().Be(0xfd);
            expandKey[11].Should().Be(0x9e);
            expandKey[12].Should().Be(0xc1);
            expandKey[13].Should().Be(0x19);
            expandKey[14].Should().Be(0xb8);
            expandKey[15].Should().Be(0xc7);
        }

        [Fact]
        public void ConfirmSystemCryptographyFunctionality()
        {
            const string key = "YELLOW SUBMARINE";
            const string plaintext = "Carol of the bells";

            var ciphertext = SystemCryptographyEncrypt(plaintext, key);
            var decryptedPlaintext = SystemCryptographyDecrypt(ciphertext, key);

            decryptedPlaintext.Should().Be(decryptedPlaintext);
        }

        [Fact]
        public void Decrypt_ChallengeTextUsingSystemCryptography()
        {
            const string key = "YELLOW SUBMARINE";
            var challengeText = File.ReadAllText("TestData/Set1/7.txt");

            var challengePlainText = SystemCryptographyDecrypt(challengeText, key);

            challengePlainText.Should().Contain("Play that funky music");
        }

        private static string SystemCryptographyEncrypt(string plaintext, string key)
        {
            var aes = Aes.Create();
            aes.Key = Encoding.ASCII.GetBytes(key);
            aes.Mode = CipherMode.ECB;
            var encryptor = aes.CreateEncryptor();

            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plaintext);
                    }

                    var encrypted = msEncrypt.ToArray();
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        private static string SystemCryptographyDecrypt(string ciphertext, string key)
        {
            var aes = Aes.Create();
            aes.Key = Encoding.ASCII.GetBytes(key);
            aes.Mode = CipherMode.ECB;
            var decryptor = aes.CreateDecryptor();

            using (var msDecrypt = new MemoryStream(Convert.FromBase64String(ciphertext)))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}