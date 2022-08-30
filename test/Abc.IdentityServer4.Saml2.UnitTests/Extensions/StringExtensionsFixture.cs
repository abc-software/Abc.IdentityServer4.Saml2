using FluentAssertions;
using IdentityServer4.Extensions;
using System.Linq;
using Xunit;

namespace Abc.IdentityServer4.Saml2.UnitTests
{
    public class StringExtensionsFixture {
        #region GetOrigin
        [Theory]
        [InlineData("http://idsvr.com", "http://idsvr.com")]
        [InlineData("http://idsvr.com/", "http://idsvr.com")]
        [InlineData("http://idsvr.com/test", "http://idsvr.com")]
        [InlineData("http://idsvr.com/test/resource", "http://idsvr.com")]
        [InlineData("http://idsvr.com:8080", "http://idsvr.com:8080")]
        [InlineData("http://idsvr.com:8080/", "http://idsvr.com:8080")]
        [InlineData("http://idsvr.com:8080/test", "http://idsvr.com:8080")]
        [InlineData("http://idsvr.com:8080/test/resource", "http://idsvr.com:8080")]
        [InlineData("http://127.0.0.1", "http://127.0.0.1")]
        [InlineData("http://127.0.0.1/", "http://127.0.0.1")]
        [InlineData("http://127.0.0.1/test", "http://127.0.0.1")]
        [InlineData("http://127.0.0.1/test/resource", "http://127.0.0.1")]
        [InlineData("http://127.0.0.1:8080", "http://127.0.0.1:8080")]
        [InlineData("http://127.0.0.1:8080/", "http://127.0.0.1:8080")]
        [InlineData("http://127.0.0.1:8080/test", "http://127.0.0.1:8080")]
        [InlineData("http://127.0.0.1:8080/test/resource", "http://127.0.0.1:8080")]
        [InlineData("http://localhost", "http://localhost")]
        [InlineData("http://localhost/", "http://localhost")]
        [InlineData("http://localhost/test", "http://localhost")]
        [InlineData("http://localhost/test/resource", "http://localhost")]
        [InlineData("http://localhost:8080", "http://localhost:8080")]
        [InlineData("http://localhost:8080/", "http://localhost:8080")]
        [InlineData("http://localhost:8080/test", "http://localhost:8080")]
        [InlineData("http://localhost:8080/test/resource", "http://localhost:8080")]

        [InlineData("https://idsvr.com", "https://idsvr.com")]
        [InlineData("https://idsvr.com/", "https://idsvr.com")]
        [InlineData("https://idsvr.com/test", "https://idsvr.com")]
        [InlineData("https://idsvr.com/test/resource", "https://idsvr.com")]
        [InlineData("https://idsvr.com:8080", "https://idsvr.com:8080")]
        [InlineData("https://idsvr.com:8080/", "https://idsvr.com:8080")]
        [InlineData("https://idsvr.com:8080/test", "https://idsvr.com:8080")]
        [InlineData("https://idsvr.com:8080/test/resource", "https://idsvr.com:8080")]
        [InlineData("https://127.0.0.1", "https://127.0.0.1")]
        [InlineData("https://127.0.0.1/", "https://127.0.0.1")]
        [InlineData("https://127.0.0.1/test", "https://127.0.0.1")]
        [InlineData("https://127.0.0.1/test/resource", "https://127.0.0.1")]
        [InlineData("https://127.0.0.1:8080", "https://127.0.0.1:8080")]
        [InlineData("https://127.0.0.1:8080/", "https://127.0.0.1:8080")]
        [InlineData("https://127.0.0.1:8080/test", "https://127.0.0.1:8080")]
        [InlineData("https://127.0.0.1:8080/test/resource", "https://127.0.0.1:8080")]
        [InlineData("https://localhost", "https://localhost")]
        [InlineData("https://localhost/", "https://localhost")]
        [InlineData("https://localhost/test", "https://localhost")]
        [InlineData("https://localhost/test/resource", "https://localhost")]
        [InlineData("https://localhost:8080", "https://localhost:8080")]
        [InlineData("https://localhost:8080/", "https://localhost:8080")]
        [InlineData("https://localhost:8080/test", "https://localhost:8080")]
        [InlineData("https://localhost:8080/test/resource", "https://localhost:8080")]

        [InlineData("test://idsvr.com", null)]
        [InlineData("test://idsvr.com/", null)]
        [InlineData("test://idsvr.com/test", null)]
        [InlineData("test://idsvr.com/test/resource", null)]
        [InlineData("test://idsvr.com:8080", null)]
        [InlineData("test://idsvr.com:8080/", null)]
        [InlineData("test://idsvr.com:8080/test", null)]
        [InlineData("test://idsvr.com:8080/test/resource", null)]
        [InlineData("test://127.0.0.1", null)]
        [InlineData("test://127.0.0.1/", null)]
        [InlineData("test://127.0.0.1/test", null)]
        [InlineData("test://127.0.0.1/test/resource", null)]
        [InlineData("test://127.0.0.1:8080", null)]
        [InlineData("test://127.0.0.1:8080/", null)]
        [InlineData("test://127.0.0.1:8080/test", null)]
        [InlineData("test://127.0.0.1:8080/test/resource", null)]
        [InlineData("test://localhost", null)]
        [InlineData("test://localhost/", null)]
        [InlineData("test://localhost/test", null)]
        [InlineData("test://localhost/test/resource", null)]
        [InlineData("test://localhost:8080", null)]
        [InlineData("test://localhost:8080/", null)]
        [InlineData("test://localhost:8080/test", null)]
        [InlineData("test://localhost:8080/test/resource", null)]
        public void CheckOrigin(string inputUrl, string expectedOrigin) {
            var actualOrigin = inputUrl.GetOrigin();

            actualOrigin.Should().Be(expectedOrigin);
        }
        #endregion

        #region IsMissing_Present
        [Theory]
        [InlineData(null, true)]
        [InlineData("", true)]
        [InlineData(" ", true)]
        [InlineData("a", false)]
        public void CheckIsMissing(string inputUrl, bool expected)
        {
            var result = inputUrl.IsMissing();
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData(" ", false)]
        [InlineData("a", true)]
        public void CheckIsPresent(string inputUrl, bool expected)
        {
            var result = inputUrl.IsPresent();
            result.Should().Be(expected);
        }

        [Theory]
        [InlineData(null, true)]
        [InlineData("", true)]
        [InlineData(" ", true)]
        [InlineData("a", false)]
        [InlineData("0123456789", false)]
        [InlineData("01234567890", true)]
        public void CheckIsMissingOrToLong(string inputUrl, bool expected)
        {
            var result = inputUrl.IsMissingOrTooLong(10);
            result.Should().Be(expected);
        }

        #endregion

        #region Slash
        [Theory]
        [InlineData(null, null)]
        [InlineData("", "/")]
        [InlineData("http://localhost:8080/test/resource", "http://localhost:8080/test/resource/")]
        [InlineData("http://localhost:8080/test/resource/", "http://localhost:8080/test/resource/")]
        [InlineData("test/resource", "test/resource/")]
        [InlineData("/test/resource", "/test/resource/")]
        public void CheckEnsureTrailingSlash(string inputUrl, string expected)
        {
            var actualOrigin = inputUrl.EnsureTrailingSlash();

            actualOrigin.Should().Be(expected);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("", "/")]
        [InlineData("test/resource/", "/test/resource/")]
        [InlineData("/test/resource/", "/test/resource/")]
        [InlineData("test/resource", "/test/resource")]
        [InlineData("/test/resource", "/test/resource")]
        public void CheckEnsureLeadingSlash(string inputUrl, string expected)
        {
            var actualOrigin = inputUrl.EnsureLeadingSlash();

            actualOrigin.Should().Be(expected);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("test/resource/", "test/resource/")]
        [InlineData("/test/resource/", "test/resource/")]
        [InlineData("test/resource", "test/resource")]
        [InlineData("/test/resource", "test/resource")]
        public void CheckRemoveLeadingSlash(string inputUrl, string expected)
        {
            var actualOrigin = inputUrl.RemoveLeadingSlash();

            actualOrigin.Should().Be(expected);
        }
        #endregion

        #region AddQueryString
        [Theory]
        [InlineData("http://contoso.com/", "http://contoso.com/?hello=world")]
        [InlineData("http://contoso.com/someaction", "http://contoso.com/someaction?hello=world")]
        [InlineData("http://contoso.com/someaction?q=test", "http://contoso.com/someaction?q=test&hello=world")]
        [InlineData(
            "http://contoso.com/someaction?q=test#anchor",
            "http://contoso.com/someaction?q=test&hello=world#anchor")]
        [InlineData("http://contoso.com/someaction#anchor", "http://contoso.com/someaction?hello=world#anchor")]
        [InlineData("http://contoso.com/#anchor", "http://contoso.com/?hello=world#anchor")]
        [InlineData(
            "http://contoso.com/someaction?q=test#anchor?value",
            "http://contoso.com/someaction?q=test&hello=world#anchor?value")]
        [InlineData(
            "http://contoso.com/someaction#anchor?stuff",
            "http://contoso.com/someaction?hello=world#anchor?stuff")]
        [InlineData(
            "http://contoso.com/someaction?name?something",
            "http://contoso.com/someaction?name?something&hello=world")]
        [InlineData(
            "http://contoso.com/someaction#name#something",
            "http://contoso.com/someaction?hello=world#name#something")]
        public void AddQueryStringWithKeyAndValue(string uri, string expectedUri)
        {
            var result = uri.AddQueryString("hello", "world");
            result.Should().Be(expectedUri);
        }


        #endregion
    }
}
