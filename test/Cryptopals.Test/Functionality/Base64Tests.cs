using FluentAssertions;
using Xunit;

namespace Cryptopals.Test.Functionality
{
    // https://en.wikipedia.org/wiki/Base64
    // https://www.joelonsoftware.com/2003/10/08/the-absolute-minimum-every-software-developer-absolutely-positively-must-know-about-unicode-and-character-sets-no-excuses/
    public class Base64Tests
    {
        [Fact]
        public void Encode_WikipediaString()
        {
            // Man
            // 77 (0x4D), 97 (0x61), 110 (0x6E) -> hex string => 4d616e
            // 0100 1101, 0110 0001, 0110 1110
            // 19, 22, 5, 46
            // T, W, F, u

            Base64.EncodeString("Man").Should().Be("TWFu");
        }
        
        [Fact]
        public void Encode_WikipediaHex()
        {
            Base64.EncodeHex("4d616e").Should().Be("TWFu");
        }

        [Fact]
        public void Encode_WikipediaBinary()
        {
            Base64.EncodeBytes(new byte[] {77, 97, 110}).Should().Be("TWFu");
        }

        [Fact]
        public void Encode_WikipediaStringPadding()
        {
            // Ma
            // 77 (0x4D), 97 (0x61) -> hex string => 4d61
            // 0100 1101, 0110 0001
            // 19, 22, 4
            // T, W, E, =

            Base64.EncodeString("Ma").Should().Be("TWE=");
        }

        [Fact]
        public void Encode_WikipediaHexPadding()
        {
            Base64.EncodeHex("4d61").Should().Be("TWE=");
        }

        [Fact]
        public void Encode_WikipediaBytesPadding()
        {
            Base64.EncodeBytes(new byte[] {77, 97}).Should().Be("TWE=");
        }

        [Fact]
        public void Encode_WikipediaStringFullPadding()
        {
            Base64.EncodeString("M").Should().Be("TQ==");
        }

        [Fact]
        public void Encode_WikipediaFullExample()
        {
            const string data = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
            const string expected = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";
            
            Base64.EncodeString(data).Should().Be(expected);
        }

        [Fact]
        public void Decode_WikipediaString()
        {
            Base64.Decode("TWFu").Should().Be("Man");
        }

        [Fact]
        public void Decode_WikipediaStringPadding()
        {
            Base64.Decode("TWE=").Should().Be("Ma");
        }

        [Fact]
        public void Decode_WikipediaStringFullPadding()
        {
            Base64.Decode("TQ==").Should().Be("M");
        }

        [Fact]
        public void Decode_WikipediaFullExample()
        {
            const string data = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";
            const string expected = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

            Base64.Decode(data).Should().Be(expected);
        }
    }
}