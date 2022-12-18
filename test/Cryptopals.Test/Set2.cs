using System;
using System.IO;
using System.Linq;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test;

public class Set2
{
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

        var aes = AesCustom.Create(Encoding.ASCII.GetBytes(key));
        var plaintextBytes = aes.DecryptCbc(ciphertext).ToArray();

        plaintextBytes.Should().NotBeNullOrEmpty();
        var plaintext = Encoding.ASCII.GetString(plaintextBytes);
    }
}