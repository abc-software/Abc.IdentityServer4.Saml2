using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2SingleSignOnEndpointBaseFixture
    {
        private const string Category = "Saml2SingleSignOn Endpoint";
        private TestSaml2SingleSignOnEndpoint _target;

        private TestEventService _fakeEventService;
        private AuthorizationParametersMessageStoreMock _mockAuthorizationParametersMessageStore;

        private ILogger<Saml2SingleSignOnEndpoint> _fakeLogger = TestLogger.Create<Saml2SingleSignOnEndpoint>();
        private IdentityServerOptions _options = TestIdentityServerOptions.Create();
        private MockUserSession _mockUserSession = new MockUserSession();
        private ClaimsPrincipal _user = new IdentityServerUser("bob").CreatePrincipal();

        private StubSaml2RequestValidator _stubSignInRequestValidator = new StubSaml2RequestValidator();
        private StubSignInInteractionResponseGenerator _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
        private StubSignInResponseGenerator _stubSigninResponseGenerator = new StubSignInResponseGenerator();

        private HttpSaml2RequestMessage2 _signIn;
        private HttpSaml2RequestMessage2 _signOut;
        private ValidatedSaml2Request _validatedAuthorizeRequest;

        private Saml2SPOptions _spOptions = new Saml2SPOptions();

        private string ClientId = "client";
        private string AuthRequestId = "_123";

        public Saml2SingleSignOnEndpointBaseFixture()
        {
            _stubSignInRequestValidator = new StubSaml2RequestValidator();
            _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
            _stubSigninResponseGenerator = new StubSignInResponseGenerator();

            _fakeEventService = new TestEventService();

            _mockAuthorizationParametersMessageStore = new AuthorizationParametersMessageStoreMock();

            var issuer = new Saml2NameIdentifier(ClientId);
            _signIn = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Id = new Saml2Id(AuthRequestId),
                Issuer = issuer
            });
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

            _stubSigninResponseGenerator.Result = _signIn;

            _stubSignInRequestValidator.Result = new Saml2RequestValidationResult(_validatedAuthorizeRequest);

            _target = new TestSaml2SingleSignOnEndpoint(
                _mockUserSession,
                _fakeLogger,
                _stubSigninResponseGenerator,
                _stubInteractionGenerator,
                _stubSignInRequestValidator,
                _spOptions,
                _fakeEventService);
        }

        internal class TestSaml2SingleSignOnEndpoint : Saml2SingleSignOnEndpointBase
        {
            public TestSaml2SingleSignOnEndpoint(IUserSession userSession, ILogger<Saml2SingleSignOnEndpoint> logger, ISignInResponseGenerator generator, ISignInInteractionResponseGenerator interaction, ISaml2RequestValidator signinValidator, Saml2SPOptions options, IEventService events) 
                : base(userSession, logger, generator, interaction, signinValidator, options, events)
            {
            }

            public override Task<IEndpointResult> ProcessAsync(HttpContext context)
            {
                throw new NotImplementedException();
            }
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signin_request_validation_produces_error_should_display_error_page()
        {
            _stubSignInRequestValidator.Result.IsError = true;
            _stubSignInRequestValidator.Result.Error = "some_error";

            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        /*
        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_generator_consent_produces_consent_should_show_consent_page()
        {
            _stubInteractionGenerator.Response.IsConsent = true;

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<ConsentPageResult>();
        }
        */

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_error_should_show_error_page()
        {
            _stubInteractionGenerator.Response.Error = "error";

            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_error_should_show_error_page_with_error_description_if_present()
        {
            var errorDescription = "some error description";

            _stubInteractionGenerator.Response.Error = "error";
            _stubInteractionGenerator.Response.ErrorDescription = errorDescription;

            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
            var errorResult = (Endpoints.Results.ErrorPageResult)result;
            errorResult.ErrorDescription.Should().Be(errorDescription);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_login_result_should_trigger_login()
        {
            _stubInteractionGenerator.Response.IsLogin = true;

            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.LoginPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task custom_interaction_redirect_result_should_issue_redirect()
        {
            _mockUserSession.User = _user;
            _stubInteractionGenerator.Response.RedirectUrl = "http://foo.com";

            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.CustomRedirectResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task successful_signin_request_should_generate_signin_result()
        {
            var result = await _target.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signout_request_validation_produces_error_should_display_error_page()
        {
            _stubSignInRequestValidator.Result.IsError = true;
            _stubSignInRequestValidator.Result.Error = "some_error";

            var result = await _target.ProcessLogoutOutRequestAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task successful_authorization_request_should_generate_signout_result()
        {
            var result = await _target.ProcessLogoutOutRequestAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.SignOutResult>();
        }
    }
}
