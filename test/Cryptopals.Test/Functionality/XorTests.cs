using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    // AT ^ SO
    public class XorTests
    {
        [Fact]
        public void HexStrings()
        {
            const string x = "4154"; // 65 84 
            const string y = "534f"; // 83 79

            Xor.HexStrings(x, y).Should().Be("121b");
        }

        [Fact]
        public void ByteArrays()
        {
            var x = new byte[] {65, 84};
            var y = new byte[] {83, 79};

            Xor.ByteArrays(x, y).Should().BeEquivalentTo(new byte[] {18, 27});
        }
    }
}