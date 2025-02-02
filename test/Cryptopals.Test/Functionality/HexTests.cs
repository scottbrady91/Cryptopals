using System;
using System.Security.Cryptography;
using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    public class HexTests
    {
        [Fact]
        public void BytesToString_Custom()
        {
            var testBytes = new[] {Convert.ToByte(77), Convert.ToByte(97), Convert.ToByte(110)};
            const string expected = "4d616e";

            Hex.BytesToString(testBytes).Should().Be(expected);
        }

        [Fact]
        public void StringToBytes_Custom()
        {
            const string testString = "4d616e";
            var expected = new[] { Convert.ToByte(77), Convert.ToByte(97), Convert.ToByte(110) };

            Hex.StringToBytes(testString).Should().BeEquivalentTo(expected);
        }
        [Fact]
        public void BytesToString_Dotnet()
        {
            var testBytes = RandomNumberGenerator.GetBytes(32);
            var expected = Convert.ToHexString(testBytes);

            Hex.BytesToString(testBytes).Should().BeEquivalentTo(expected);
        }

        [Fact]
        public void StringToBytes_Dotnet()
        {
            var expected = RandomNumberGenerator.GetBytes(32);
            var testString = Convert.ToHexString(expected);

            Hex.StringToBytes(testString).Should().BeEquivalentTo(expected);
        }
    }
}