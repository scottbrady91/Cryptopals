using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Cryptopals;

public class AesCustom
{
    private Aes aes;
    
    private AesCustom() { }
    
    public static AesCustom Create(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;

        return new AesCustom { aes = aes };
    }
    
    public IEnumerable<byte> DecryptCbc(Span<byte> ciphertext)
    {
        var plaintext = new List<byte>();
        for (var i = 0; i < ciphertext.Length / 16; i++)
        {
            // TODO: XOR decrypted plaintext block against next ciphertext block
            
            plaintext.AddRange(aes.DecryptEcb(ciphertext.Slice(i * 16, 16), PaddingMode.None));
        }
        
        return plaintext;
    }

    public IEnumerable<byte> DecryptEcb(Span<byte> ciphertext)
    {
        var plaintext = new List<byte>();
        for (var i = 0; i < ciphertext.Length / 16; i++)
        {
            plaintext.AddRange(aes.DecryptEcb(ciphertext.Slice(i * 16, 16), PaddingMode.None));
        }
        
        return plaintext;
    }
}