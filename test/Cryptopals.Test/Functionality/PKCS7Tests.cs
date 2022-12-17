using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality;

public class PKCS7Tests
{
    [Fact]
    public void Pad_WhenAlreadyCorrectBlockSize_ExpectNoChange()
    {
        var data = new byte[16];
        RandomNumberGenerator.Fill(data);

        var paddedData = Pkcs7.Pad(data, data.Length);

        paddedData.Should().BeEquivalentTo(data);
    }

    [Theory]
    [InlineData(18, 19)]
    [InlineData(18, 20)]
    [InlineData(18, 21)]
    [InlineData(18, 22)]
    [InlineData(18, 23)]
    public void Pad_WhenNotCorrectBlockSize_ExpectPaddingCharacters(int initialSize, int blockSize)
    {
        var data = new byte[initialSize];
        RandomNumberGenerator.Fill(data);

        var paddedData = Pkcs7.Pad(data, blockSize);

        paddedData.Should().StartWith(data);
        paddedData.Length.Should().Be(blockSize);
        for (int i = 1; i <= (blockSize - initialSize); i++)
        {
            paddedData[^i].Should().Be((byte) Pkcs7.PaddingCharacter);
        }
    }
}