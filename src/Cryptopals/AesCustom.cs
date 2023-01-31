using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Cryptopals;

public class AesCustom
{
    private const int BlockSize = 16;
    private Aes aes;
    
    private AesCustom() { }
    
    public static AesCustom Create(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;  // symmetric key
        aes.BlockSize = BlockSize * 8; // block size in bits

        return new AesCustom { aes = aes };
    }
    
    /// <summary>
    /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
    /// </summary>
    public byte[] EncryptCbc(Span<byte> plaintext, Span<byte> iv)
    {
        var ciphertext = new List<byte>();
        for (var i = 0; i < plaintext.Length / BlockSize; i++)
        {
            var blockToEncrypt = plaintext.Slice(i * BlockSize, BlockSize);
            Span<byte> cbcIv;

            if (i == 0)
            {
                // first block XORed against initialization vector
                cbcIv = iv;
            }
            else
            {
                // otherwise XORed against previous ciphertext block
                cbcIv = ciphertext.Skip((i - 1) * BlockSize).Take(BlockSize).ToArray();
            }

            // XOR then encrypt
            var bytesToEncrypt = Xor.ByteArrays(blockToEncrypt, cbcIv);
            ciphertext.AddRange(EncryptEcb(bytesToEncrypt).ToArray());
        }
        
        return ciphertext.ToArray();
    }
    
    public byte[] DecryptCbc(Span<byte> ciphertext, Span<byte> iv)
    {
        var plaintext = new List<byte>();
        for (var i = 0; i < ciphertext.Length / BlockSize; i++)
        {
            var blockToDecrypt = ciphertext.Slice(i * BlockSize, BlockSize);
            Span<byte> cbcIv;
            
            if (i == 0)
            {
                // first block XORed against initialization vector
                cbcIv = iv;
            }
            else
            {
                // otherwise XORed against previous ciphertext block
                cbcIv = ciphertext.Slice((i - 1) * BlockSize, BlockSize);
            }
            
            // decrypt and then XOR
            var decryptedBytes = DecryptEcb(blockToDecrypt);
            plaintext.AddRange(Xor.ByteArrays(decryptedBytes, cbcIv));
        }

        return Pkcs7.Unpad(plaintext.ToArray()).ToArray(); // ☹️
    }

    public Span<byte> EncryptEcb(Span<byte> plaintext)
    {
        return aes.EncryptEcb(Pkcs7.Pad(plaintext, BlockSize), PaddingMode.None);
    }

    public Span<byte> DecryptEcb(Span<byte> ciphertext)
    {
        var plaintext = aes.DecryptEcb(ciphertext, PaddingMode.None);
        return Pkcs7.Unpad(plaintext);
    }

    public static bool DetectEcb(Func<byte[], byte[]> oracle)
    {
        var ciphertext = oracle(new byte[128]);
        
        var seenBlocks = new List<IEnumerable<byte>>();
        for (var i = 0; i < ciphertext.Length / 16; i++)
        {
            var block = ciphertext.Skip(i * 16).Take(16);
            if (seenBlocks.Any(x => x.SequenceEqual(block)))
            {
                return true;
            }

            seenBlocks.Add(block);
        }

        return false;
    }
}