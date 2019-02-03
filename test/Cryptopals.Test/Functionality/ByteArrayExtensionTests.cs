using System.Linq;
using System.Text;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    public class ByteArrayExtensionTests
    {
        [Fact]
        public void ToBinaryString()
        {
            var bytes = new byte[] {01, 02, 03, 04, 05};
            const string expected = "0000000100000010000000110000010000000101";

            bytes.ToBinaryString().Should().Be(expected);
        }

        [Fact]
        public void GetHammingDistance_UsingCryptopalsExample()
        {
            var x = Encoding.ASCII.GetBytes("this is a test");
            var y = Encoding.ASCII.GetBytes("wokka wokka!!!");

            x.GetHammingDistance(y).Should().Be(37);
        }

        [Fact]
        public void Chunk_WhenArrayDivisibleByKeySize_ExpectCorrectBlocks()
        {
            var first = new byte[] {01, 02, 03};
            var second = new byte[] {04, 05, 06};
            var all = first.Concat(second);

            var blocks = all.Chunk(3);

            blocks[0].Should().BeEquivalentTo(first);
            blocks[1].Should().BeEquivalentTo(second);
        }

        [Fact]
        public void Chunk_WhenArrayNotDivisibleByKeySize_ExpectCorrectBlocks()
        {
            var first = new byte[] {01, 02, 03};
            var second = new byte[] {04};
            var all = first.Concat(second);

            var blocks = all.Chunk(3);

            blocks[0].Should().BeEquivalentTo(first);
            blocks[1].Should().BeEquivalentTo(second);
        }

        [Fact]
        public void ToBlock()
        {
            var bytes = new byte[]
            {
                01, 02, 03, 04,
                05, 06, 07, 08,
                09, 10, 11, 12,
                13, 14, 15, 16
            };

            var block = bytes.ToBlock();

            block[0, 0].Should().Be(1);
            block[0, 1].Should().Be(2);
            block[0, 2].Should().Be(3);
            block[0, 3].Should().Be(4);
            block[1, 0].Should().Be(5);
            block[1, 1].Should().Be(6);
        }
    }
}