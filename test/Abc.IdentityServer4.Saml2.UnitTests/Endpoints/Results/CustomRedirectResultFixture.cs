using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer.Extensions;
using Abc.IdentityServer.Saml2.Validation;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer.Saml2.Endpoints.Results.UnitTests
{
    public class CutomRedirectResultFixture
    {
        private CustomRedirectResult _target;
        private IdentityServerOptions _options;
        private IClock _clock = new StubClock();
        private DefaultHttpContext _context;
        private AuthorizationParametersMessageStoreMock _authorizationParametersMessageStore;
        private ValidatedSaml2Request _request;
        private IServerUrls _urls;

        public CutomRedirectResultFixture()
        {
            _context = new DefaultHttpContext();
            _context.RequestServices = new ServiceCollection().BuildServiceProvider();

            _options = new IdentityServerOptions();

            _authorizationParametersMessageStore = new AuthorizationParametersMessageStoreMock();

            _request = new ValidatedSaml2Request();
            _request.Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), "some_request", IdentityModel.Http.HttpDeliveryMethods.PostRequest);

            _urls = new MockServerUrls()
            {
                Origin = "https://server",
                BasePath = "/".RemoveLeadingSlash(), // Duende build wrong baseUrl
            };
        }

        [Fact]
        public void cutomredirect_ctor()
        {
            {
                Action action = () =>
                {
                    _target = new CustomRedirectResult(null, "https://server/cutom", _options, _clock, _urls, _authorizationParametersMessageStore);
                };

                action.Should().Throw<ArgumentNullException>();
            }
            {
                Action action = () =>
                {
                    _target = new CustomRedirectResult(_request, null, _options, _clock, _urls, _authorizationParametersMessageStore);
                };

                action.Should().Throw<ArgumentNullException>();
            }
        }

        [Fact]
        public async Task external_cutomredirect_should_redirect_to_page_and_passs_info()
        {
            _target = new CustomRedirectResult(_request, "https://server/custom", _options, _clock, _urls, _authorizationParametersMessageStore);

            await _target.ExecuteAsync(_context);

            _authorizationParametersMessageStore.Messages.Count.Should().Be(1);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/custom");

            var query = QueryHelpers.ParseQuery(new Uri(location).Query);
            query["returnUrl"].First().Should().StartWith("https://server/saml2/callback");
            query["returnUrl"].First().Should().Contain("?authzId=" + _authorizationParametersMessageStore.Messages.First().Key);
        }

        [Fact]
        public async Task local_cutomredirect_should_redirect_to_page_and_passs_info()
        {
            _target = new CustomRedirectResult(_request, "~/custom", _options, _clock, _urls, _authorizationParametersMessageStore);

            await _target.ExecuteAsync(_context);

            _authorizationParametersMessageStore.Messages.Count.Should().Be(1);
            _context.Response.StatusCode.Should().Be(302);

            var location = _context.Response.Headers["Location"].First();
            location.Should().StartWith("https://server/custom");

            var query = QueryHelpers.ParseQuery(new Uri(location).Query);
            query["returnUrl"].First().Should().StartWith("/saml2/callback");
            query["returnUrl"].First().Should().Contain("?authzId=" + _authorizationParametersMessageStore.Messages.First().Key);
        }
    }
}