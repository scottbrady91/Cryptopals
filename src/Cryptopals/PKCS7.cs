using System;

namespace Cryptopals;

// ReSharper disable once InconsistentNaming
public static class Pkcs7
{
    public const byte PaddingCharacter = 4;
    
    public static Span<byte> Pad(Span<byte> data, int blockSize)
    {
        var mod = blockSize % data.Length;
        if (mod == 0) return data;

        var paddedBytes = new byte[data.Length + mod];
        data.CopyTo(paddedBytes);
        
        for (var i = 1; i <= mod; i++)
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