using System;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    public class HexTests
    {
        [Fact]
        public void BytesToString()
        {
            var testBytes = new[] {Convert.ToByte(77), Convert.ToByte(97), Convert.ToByte(110)};
            const string expected = "4d616e";

            Hex.BytesToString(testBytes).Should().Be(expected);
        }

        [Fact]
        public void StringToBytes()
        {
            const string testString = "4d616e";
            var expected = new[] { Convert.ToByte(77), Convert.ToByte(97), Convert.ToByte(110) };

            Hex.StringToBytes(testString).Should().BeEquivalentTo(expected);
        }
    }
}