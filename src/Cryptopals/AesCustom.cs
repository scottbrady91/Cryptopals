using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Cryptopals;

public class AesCustom
{
    private int blockSize;
    private Aes aes;
    
    private AesCustom() { }
    
    public static AesCustom Create(byte[] key, int blockSize = 16)
    {
        var aes = Aes.Create();
        aes.Key = key;  // symmetric key
        aes.BlockSize = blockSize * 8; // block size in bits

        return new AesCustom { aes = aes, blockSize = blockSize };
    }
    
    /// <summary>
    /// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
    /// </summary>
    public byte[] EncryptCbc(Span<byte> plaintext, Span<byte> iv)
    {
        var ciphertext = new List<byte>();
        byte[] previousEncryptedBlock = null;
        for (var i = 0; i < plaintext.Length / blockSize; i++)
        {
            var blockToEncrypt = plaintext.Slice(i * blockSize, blockSize);
            Span<byte> currentIv;

            // first block XORed against initialization vector
            if (i == 0) currentIv = iv;
            // otherwise XORed against previous ciphertext block
            else currentIv = previousEncryptedBlock;

            // XOR then encrypt
            var bytesToEncrypt = Xor.ByteArrays(blockToEncrypt, currentIv);
            var encryptedBlock = aes.EncryptEcb(Pkcs7.Pad(bytesToEncrypt, blockSize), PaddingMode.None);
            
            ciphertext.AddRange(encryptedBlock);
            previousEncryptedBlock = encryptedBlock;
        }
        
        return ciphertext.ToArray();
    }
    
    public byte[] DecryptCbc(Span<byte> ciphertext, Span<byte> iv)
    {
        var plaintext = new List<byte>();
        Span<byte> previousEncryptedBlock = null;
        for (var i = 0; i < ciphertext.Length / blockSize; i++)
        {
            var blockToDecrypt = ciphertext.Slice(i * blockSize, blockSize);
            Span<byte> currentIv;
            
            if (i == 0)
            {
                // first block XORed against initialization vector
                currentIv = iv;
            }
            else
            {
                // otherwise XORed against previous ciphertext block
                currentIv = previousEncryptedBlock;
            }
            
            // decrypt and then XOR
            var decryptedBytes = DecryptEcb(blockToDecrypt);
            plaintext.AddRange(Xor.ByteArrays(decryptedBytes, currentIv));
            
            previousEncryptedBlock = blockToDecrypt;
        }

        return Pkcs7.Unpad(plaintext.ToArray()).ToArray(); // ☹️
    }

    public Span<byte> EncryptEcb(Span<byte> plaintext)
    {
        return aes.EncryptEcb(Pkcs7.Pad(plaintext, blockSize), PaddingMode.None);
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