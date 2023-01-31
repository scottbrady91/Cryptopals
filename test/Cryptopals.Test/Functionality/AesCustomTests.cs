using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality;

public class AesCustomTests
{
    [Fact]
    public void ECB_EncryptAndDecrypt()
    {
        var key = new byte[16];
        RandomNumberGenerator.Fill(key);
        
        var plaintext = new byte[256];
        RandomNumberGenerator.Fill(plaintext);

        var aes = AesCustom.Create(key);
        var ciphertext = aes.EncryptEcb(plaintext);
        var decryptedPlaintext = aes.DecryptEcb(ciphertext);

        decryptedPlaintext.SequenceEqual(plaintext).Should().BeTrue();
    }
    
    [Fact]
    public void ECB_WhenPaddingRequired_EncryptAndDecrypt()
    {
        var key = new byte[16];
        RandomNumberGenerator.Fill(key);
        
        var plaintext = new byte[2];
        RandomNumberGenerator.Fill(plaintext);

        var aes = AesCustom.Create(key);
        var ciphertext = aes.EncryptEcb(plaintext);
        var decryptedPlaintext = aes.DecryptEcb(ciphertext);

        decryptedPlaintext.SequenceEqual(plaintext).Should().BeTrue();
    }
    
    [Fact]
    public void DecryptCbc_ExpectAbleToDecryptSystemSecurityCryptographyAes()
    {
        var key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
        var plaintext = Encoding.ASCII.GetBytes("GOT MORE SOUL THAN A SOCK WITH A");
        var iv = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        var systemCiphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.None);
        
        var decryptedPlaintext = AesCustom.Create(key).DecryptCbc(systemCiphertext, iv);
        
        decryptedPlaintext.Should().BeEquivalentTo(plaintext);
    }
    
    [Fact]
    public void EncryptCbc_ExpectDecryptableBySystemSecurityCryptographyAes()
    {
        var key = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
        var plaintext = Encoding.ASCII.GetBytes("GOT MORE SOUL THAN A SOCK WITH A");
        var iv = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        var ciphertext = AesCustom.Create(key).EncryptCbc(plaintext, iv);

        var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        var decryptedPlaintext = aes.DecryptCbc(ciphertext.ToArray(), iv, PaddingMode.None);

        decryptedPlaintext.Should().BeEquivalentTo(plaintext);
    }

    [Fact]
    public void CBC_EncryptAndDecrypt()
    {
        var key = new byte[16];
        RandomNumberGenerator.Fill(key);
        
        var plaintext = new byte[32];
        RandomNumberGenerator.Fill(plaintext);

        var iv = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        var aes = AesCustom.Create(key);
        var ciphertext = aes.EncryptCbc(plaintext, iv);
        var decryptedPlaintext = aes.DecryptCbc(ciphertext.ToArray(), iv);
        
        decryptedPlaintext.Should().BeEquivalentTo(plaintext);
    }
}