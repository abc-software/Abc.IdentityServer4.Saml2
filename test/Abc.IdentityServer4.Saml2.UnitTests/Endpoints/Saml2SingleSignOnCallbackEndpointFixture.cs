using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Endpoints;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2SingleSignOnCallbackEndpointFixture
    {
        private const string Category = "Saml2SingleSignOnCallback Endpoint";
        private Saml2SingleSignOnCallbackEndpoint _target;

        private TestEventService _fakeEventService;
        private AuthorizationParametersMessageStoreMock _mockAuthorizationParametersMessageStore;
        private MockConsentMessageStore _mockUserConsentResponseMessageStore;

        private MockUserSession _mockUserSession = new MockUserSession();
        private ClaimsPrincipal _user = new IdentityServerUser("bob").CreatePrincipal();

        private StubSaml2RequestValidator _stubSignInRequestValidator = new StubSaml2RequestValidator();
        private StubSignInInteractionResponseGenerator _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
        private StubSignInResponseGenerator _stubSigninResponseGenerator = new StubSignInResponseGenerator();

        private HttpSaml2RequestMessage2 _signIn;
        private ValidatedSaml2Request _validatedAuthorizeRequest;

        private Saml2SPOptions _spOptions = new Saml2SPOptions();
        private DefaultHttpContext _context;

        private string ClientId = "client";
        private string AuthRequestId = "_123";

        public Saml2SingleSignOnCallbackEndpointFixture()
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

            var issuer = new Saml2NameIdentifier(ClientId);
            _signIn = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest() { 
                Id = new Saml2Id(AuthRequestId),
                Issuer = issuer 
            });

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

            _stubSigninResponseGenerator.Result = _signIn;

            _stubSignInRequestValidator.Result = new Saml2RequestValidationResult(_validatedAuthorizeRequest);

            _target = new Saml2SingleSignOnCallbackEndpoint(
                _mockUserSession,
                TestLogger.Create<Saml2SingleSignOnCallbackEndpoint>(),
                _stubSigninResponseGenerator,
                _stubInteractionGenerator,
                _stubSignInRequestValidator,
                _mockUserConsentResponseMessageStore,
                _mockAuthorizationParametersMessageStore,
                _spOptions,
                _fakeEventService);
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
        public async Task signin_after_consent_path_should_return_signin_result()
        {
            var parameters = new NameValueCollection()
            {
                { "client_id", ClientId },
                { "nonce", AuthRequestId },
            };
            var request = new ConsentRequest(parameters, _user.GetSubjectId());
            _mockUserConsentResponseMessageStore.Messages.Add(request.Id, new Message<ConsentResponse>(new ConsentResponse(), DateTime.UtcNow));

            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signin_after_login_path_should_return_signin_result()
        {
            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            _mockUserSession.User = _user;

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task sigin_invalid_data_should_return_error_page()
        {
            _signIn = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("urn:issuer")));

            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signin_missing_data_should_return_error_page()
        {
            var key = Guid.NewGuid().ToString();

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task consent_missing_consent_data_should_return_error_page()
        {
            var parameters = new NameValueCollection()
            {
                { "client_id", ClientId },
                { "nonce", AuthRequestId },
            };
            var request = new ConsentRequest(parameters, _user.GetSubjectId());
            _mockUserConsentResponseMessageStore.Messages.Add(request.Id, new Message<ConsentResponse>(null, DateTime.UtcNow));

            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task valid_consent_message_should_cleanup_consent_cookie()
        {
            var parameters = new NameValueCollection()
            {
                { "client_id", ClientId },
                { "nonce", AuthRequestId },
            };
            var request = new ConsentRequest(parameters, _user.GetSubjectId());
            _mockUserConsentResponseMessageStore.Messages.Add(request.Id, new Message<ConsentResponse>(new ConsentResponse() { ScopesValuesConsented = new string[] { "api1", "api2" } }, DateTime.UtcNow));

            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            _mockUserConsentResponseMessageStore.Messages.Count.Should().Be(0);
            _mockAuthorizationParametersMessageStore.Messages.Count.Should().Be(0);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task valid_consent_message_should_return_authorize_result()
        {
            var parameters = new NameValueCollection()
            {
                { "client_id", ClientId },
                { "nonce", AuthRequestId },
            };

            var request = new ConsentRequest(parameters, _user.GetSubjectId());
            _mockUserConsentResponseMessageStore.Messages.Add(request.Id, new Message<ConsentResponse>(new ConsentResponse() { ScopesValuesConsented = new string[] { "api1", "api2" } }, DateTime.UtcNow));

            var key = Guid.NewGuid().ToString();
            _mockAuthorizationParametersMessageStore.Messages.Add(key, new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            _mockUserSession.User = _user;

            _context.Request.Method = "GET";
            _context.Request.Path = new PathString("/saml2/callback");
            _context.Request.QueryString = new QueryString("?authzId=" + key);

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

    }
}
