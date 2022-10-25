using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityServer4;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2SingleLogOutCallbackEndpointFixture
    {
        private const string Category = "Saml2SingleLogOutCallback Endpoint";
        private Saml2SingleLogOutCallbackEndpoint _target;

        private TestEventService _fakeEventService;
        private AuthorizationParametersMessageStoreMock _mockAuthorizationParametersMessageStore;
        private MockConsentMessageStore _mockUserConsentResponseMessageStore;

        private MockUserSession _mockUserSession = new MockUserSession();
        private ClaimsPrincipal _user = new IdentityServerUser("bob").CreatePrincipal();

        private StubSaml2RequestValidator _stubSignInRequestValidator = new StubSaml2RequestValidator();
        private StubSignInInteractionResponseGenerator _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
        private StubSignInResponseGenerator _stubSigninResponseGenerator = new StubSignInResponseGenerator();

        private HttpSaml2RequestMessage2 _signOut;
        private ValidatedSaml2Request _validatedAuthorizeRequest;

        private Saml2SPOptions _spOptions = new Saml2SPOptions();
        private DefaultHttpContext _context;
        private StubLogoutResponseGenerator _signoutGenerator = new StubLogoutResponseGenerator();

        private string ClientId = "client";

        public Saml2SingleLogOutCallbackEndpointFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");

            _stubSignInRequestValidator = new StubSaml2RequestValidator();
            _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
            _stubSigninResponseGenerator = new StubSignInResponseGenerator();

            _fakeEventService = new TestEventService();

            _mockAuthorizationParametersMessageStore = new AuthorizationParametersMessageStoreMock();
            _mockUserConsentResponseMessageStore = new MockConsentMessageStore();

            var issuer = new Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier(ClientId);
            _signOut = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(issuer));

            _validatedAuthorizeRequest = new ValidatedSaml2Request()
            {
                ReplyUrl = "http://client/callback",
                ClientId = ClientId,
                Client = new Client
                {
                    ClientId = ClientId,
                    ClientName = "Test Client"
                },
                //Raw = _params,
                Subject = _user
            };

            _stubSigninResponseGenerator.Result = _signOut;

            _stubSignInRequestValidator.Result = new Saml2RequestValidationResult(_validatedAuthorizeRequest);

            _target = new Saml2SingleLogOutCallbackEndpoint(
                _mockUserSession,
                TestLogger.Create<Saml2SingleLogOutCallbackEndpoint>(),
                _stubSigninResponseGenerator,
                _stubInteractionGenerator,
                _stubSignInRequestValidator,
                _mockAuthorizationParametersMessageStore,
                _spOptions,
                _signoutGenerator,
                _fakeEventService
                );
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task post_to_entry_point_should_return_405()
        {
            _context.Request.Method = "POST";

            var result = await _target.ProcessAsync(_context);

            var statusCode = result as StatusCodeResult;
            statusCode.Should().NotBeNull();
            statusCode.StatusCode.Should().Be(405);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task valid_logout_should_return_logout_response()
        {
            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signOut.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/slo/callback");
            _context.Request.QueryString = new QueryString("?requestId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task valid_logout_should_cleanup_store()
        {
            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signOut.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/slo/callback");
            _context.Request.QueryString = new QueryString("?requestId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();

            _mockAuthorizationParametersMessageStore.Messages.Count.Should().Be(0);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task missing_request_should_return_error_page()
        {
            var key = Guid.NewGuid().ToString();

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/slo/callback");
            _context.Request.QueryString = new QueryString("?requestId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task empty_request_should_return_error_page()
        {
            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/slo/callback");
            _context.Request.QueryString = new QueryString("?requestId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task invalid_requestId_should_return_error_page()
        {
            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/slo/callback");

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }
    }
}
