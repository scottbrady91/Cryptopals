using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    public class StringExtensionTests
    {
        [Fact]
        public void GetHammingDistance_UsingCryptopalsExample()
        {
            var x = "this is a test";
            var y = "wokka wokka!!!";

            x.GetHammingDistance(y).Should().Be(37);
        }
    }
}