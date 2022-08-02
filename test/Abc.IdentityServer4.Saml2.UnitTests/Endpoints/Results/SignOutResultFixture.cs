using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
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
    public class SignOutResultFixture
    {
        private SignOutResult _target;
        private IdentityServerOptions _options;
        private DefaultHttpContext _context;
        private ISystemClock _clock;
        private ValidatedSaml2Request _request;
        private MockMessageStore<LogoutMessage> _logoutMessageStore;
        private IAuthorizationParametersMessageStore _athorizationparametersMessageStore;

        public SignOutResultFixture()
        {
            _options = new IdentityServerOptions();
            _options.UserInteraction.LogoutUrl = "~/logout";
            _options.UserInteraction.LogoutIdParameter = "logoutId";

            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();

            _clock = new StubClock();

            _request = new ValidatedSaml2Request();
            _request.Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server"), "some_request", IdentityModel.Http.HttpDeliveryMethods.PostRequest);

            _logoutMessageStore = new MockMessageStore<LogoutMessage>();

            _athorizationparametersMessageStore = new AuthorizationParametersMessageStoreMock();

            _target = new SignOutResult(_request, _options, _clock, _logoutMessageStore, _athorizationparametersMessageStore);
        }

        [Fact]
        public void signout_ctor()
        {
            Action action = () =>
            {
                _target = new SignOutResult(null, _options, _clock, _logoutMessageStore, _athorizationparametersMessageStore);
            };

            action.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public async Task signout_user_authenticated_should_redirect_to_logout_page_and_passs_info()
        {
            _request.Client = new Client
            {
                ClientId = "client",
                ClientName = "Test Client"
            };

            await _target.ExecuteAsync(_context);

            _logoutMessageStore.Messages.Count.Should().Be(1);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/logout");

            var query = QueryHelpers.ParseQuery(new Uri(location).Query);
            query["logoutId"].First().Should().Be(_logoutMessageStore.Messages.First().Key);
        }

        [Fact]
        public async Task signout_has_authenticated_clients_should_redirect_to_logout_page_and_passs_info()
        {
            _request.ClientIds = new string[] { "urn:owinrp" };

            await _target.ExecuteAsync(_context);

            _logoutMessageStore.Messages.Count.Should().Be(1);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/logout");

            var query = QueryHelpers.ParseQuery(new Uri(location).Query);
            query["logoutId"].First().Should().Be(_logoutMessageStore.Messages.First().Key);
        }

        [Fact]
        public async Task signout_user_not_authenticated_should_redirect_to_logout_page()
        {
            await _target.ExecuteAsync(_context);

            _logoutMessageStore.Messages.Count.Should().Be(0);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/logout");
        }
    }
}