using FluentAssertions;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results.UnitTests
{
    public class ErrorPageResultFixture
    {
        private ErrorPageResult _target;
        private IdentityServerOptions _options;
        private MockMessageStore<ErrorMessage> _errorMessageStore;
        private ISystemClock _clock = new StubClock();
        private DefaultHttpContext _context;

        public ErrorPageResultFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();

            _options = new IdentityServerOptions();
            _options.UserInteraction.ErrorUrl = "~/error";
            _options.UserInteraction.ErrorIdParameter = "errorId";

            _errorMessageStore = new MockMessageStore<ErrorMessage>();

            _target = new ErrorPageResult("some_error", "some_desciption", _options, _clock, _errorMessageStore);
        }

        [Fact]
        public async Task error_should_redirect_to_error_page_and_passs_info()
        {
            _target.Error.Should().Be("some_error");
            _target.ErrorDescription.Should().Be("some_desciption");

            await _target.ExecuteAsync(_context);

            _errorMessageStore.Messages.Count.Should().Be(1);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/error");

            var query = QueryHelpers.ParseQuery(new Uri(location).Query);
            var message = _errorMessageStore.Messages.First();
            query["errorId"].First().Should().Be(message.Key);
            message.Value.Data.Error.Should().Be("some_error");
            message.Value.Data.ErrorDescription.Should().Be("some_desciption");
        }
    }
}