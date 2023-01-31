using System;

namespace Cryptopals;

// ReSharper disable once InconsistentNaming
public static class Pkcs7
{
    public const byte PaddingCharacter = 4;
    
    // data.Length = 17
    // blockSize = 16
    public static Span<byte> Pad(Span<byte> data, int blockSize)
    {
        int numberOfPaddingCharacters;
        
        // when not padding individual blocks
        if (blockSize < data.Length)
        {
            // only use at final block
            numberOfPaddingCharacters = blockSize - data.Slice(blockSize * (data.Length / blockSize)).Length;
        }
        else
        {
            numberOfPaddingCharacters = blockSize - data.Length;
        }

        var paddedBytes = new byte[data.Length + numberOfPaddingCharacters];
        data.CopyTo(paddedBytes);
        
        for (var i = 1; i <= numberOfPaddingCharacters; i++)
        {
            paddedBytes[^i] = PaddingCharacter;
        }

        return paddedBytes;
    }

    public static Span<byte> Unpad(Span<byte> data)
    {
        if (data[^1] != PaddingCharacter) return data;
        
        return data.Trim(PaddingCharacter);
    }
}