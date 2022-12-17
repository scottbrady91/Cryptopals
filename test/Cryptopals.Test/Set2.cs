using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test;

public class Set2
{
    [Fact]
    public void Challenge1() // Implement PKCS#7 padding
    {
        const string block = "YELLOW SUBMARINE";
        const string expectedPaddedBlock = "YELLOW SUBMARINE\x04\x04\x04\x04"; // padded to 20 bytes

        var paddedBytes = PKCS7.Pad(Encoding.ASCII.GetBytes(block), 20);

        Encoding.ASCII.GetString(paddedBytes).Should().Be(expectedPaddedBlock);
    } 
}