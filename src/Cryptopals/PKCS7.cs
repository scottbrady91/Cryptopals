using System;

namespace Cryptopals;

// ReSharper disable once InconsistentNaming
public static class Pkcs7
{
    public const char PaddingCharacter = '\x04';
    
    /// <summary>
    /// 🤢
    /// </summary>
    public static byte[] Pad(byte[] data, int blockSize)
    {
        var mod = blockSize % data.Length;
        if (mod == 0) return data;

        var paddedBytes = new byte[data.Length + mod];
        Array.Copy(data, paddedBytes, data.Length);

        for (var i = 1; i <= mod; i++)
        {
            paddedBytes[^i] = (byte) PaddingCharacter;
        }

        return paddedBytes;
    }
}