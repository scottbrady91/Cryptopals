using System;
using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality;

public class Pkcs7Tests
{
    [Fact]
    public void Pad_WhenAlreadyCorrectBlockSize_ExpectNoChange()
    {
        var data = new byte[16];
        RandomNumberGenerator.Fill(data);

        var paddedData = Pkcs7.Pad(data, data.Length);

        paddedData.SequenceEqual(data).Should().BeTrue();
    }

    [Theory]
    [InlineData(18, 19)]
    [InlineData(18, 20)]
    [InlineData(18, 21)]
    [InlineData(18, 22)]
    [InlineData(18, 23)]
    public void Pad_WhenNotCorrectBlockSizeAndDataSmallerThanBlockSize_ExpectDataExpandedWithPaddingCharacters(int initialSize, int blockSize)
    {
        var data = new byte[initialSize];
        RandomNumberGenerator.Fill(data);

        var paddedData = Pkcs7.Pad(data, blockSize).ToArray();

        paddedData.Should().StartWith(data);
        paddedData.Length.Should().Be(blockSize);
        for (int i = 1; i <= (blockSize - initialSize); i++)
        {
            paddedData[^i].Should().Be(Pkcs7.PaddingCharacter);
        }
    }

    [Theory]
    [InlineData(17, 16, 2)]
    [InlineData(18, 16, 2)]
    [InlineData(19, 16, 2)]
    [InlineData(20, 16, 2)]
    [InlineData(21, 16, 2)]
    [InlineData(22, 16, 2)]
    [InlineData(97, 16, 7)]
    public void Pad_WhenNotCorrectBlockSizeAndDataLargerThanBlockSize_ExpectDataExpandedWithPaddingCharacters(int initialSize, int blockSize, int expectedSize)
    {
        var data = new byte[initialSize];
        RandomNumberGenerator.Fill(data);

        var paddedData = Pkcs7.Pad(data, blockSize).ToArray();

        paddedData.Should().StartWith(data);
        paddedData.Length.Should().Be(blockSize * expectedSize);
        paddedData[^1].Should().Be(Pkcs7.PaddingCharacter);
    }
    
    [Fact]
    public void Unpad_WhenDataDoesNotEndWithPaddingCharacters_ExpectNoChange()
    {
        var data = new byte[16];
        RandomNumberGenerator.Fill(data);
        data[^1] = 1;

        var paddedData = Pkcs7.Unpad(data);

        paddedData.SequenceEqual(data).Should().BeTrue();
    }

    [Fact]
    public void Unpad_WhenDataEndsWithPaddingCharacters_ExpectNoChange()
    {
        const int initialSize = 64;
        var data = new byte[initialSize];
        RandomNumberGenerator.Fill(data);

        var numberOfPaddingCharacters = RandomNumberGenerator.GetInt32(42);
        for (var i = 1; i <= numberOfPaddingCharacters; i++)
        {
            data[^i] = Pkcs7.PaddingCharacter;
        }

        var unpaddedData = Pkcs7.Unpad(data);

        unpaddedData.Length.Should().Be(initialSize - numberOfPaddingCharacters);
        unpaddedData[^1].Should().NotBe(Pkcs7.PaddingCharacter);
    }
}