using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Endpoints;
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
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoint.UnitTests
{
    public class Saml2SingleSignOnEndpointFixture
    {
        private const string Category = "Saml2SingleSignOn Endpoint";
        private Saml2SingleSignOnEndpoint _subject;

        private TestEventService _fakeEventService;
        private AuthorizationParametersMessageStoreMock _mockAuthorizationParametersMessageStore;
        private MockConsentMessageStore _mockUserConsentResponseMessageStore;
        private HttpSaml2MessageSerializer _serialzer = new HttpSaml2MessageSerializer(null);

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
        private ILogoutResponseGenerator _signoutGenerator;

        public Saml2SingleSignOnEndpointFixture()
        {
            _stubSignInRequestValidator = new StubSaml2RequestValidator();
            _stubInteractionGenerator = new StubSignInInteractionResponseGenerator();
            _stubSigninResponseGenerator = new StubSignInResponseGenerator();

            _fakeEventService = new TestEventService();

            _mockAuthorizationParametersMessageStore = new AuthorizationParametersMessageStoreMock();
            _mockUserConsentResponseMessageStore = new MockConsentMessageStore();

            //_signIn = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"),  { Wa = "wsignin1.0", Wtrealm = "urn:realm" };
            //_signOut = new WsFederationMessage() { Wa = "wsignout1.0", Wtrealm = "urn:realm", Wreply = "http://localhost/" };

            _validatedAuthorizeRequest = new ValidatedSaml2Request()
            {
                ReplyUrl = "http://client/callback",
                ClientId = "client",
                Client = new Client
                {
                    ClientId = "client",
                    ClientName = "Test Client"
                },
                //Raw = _params,
                Subject = _user
            };

            _stubSigninResponseGenerator.Result = new HttpSaml2ResponseMessage2(new Uri("https://fake"), "some_repsonse");

            _stubSignInRequestValidator.Result = new Saml2RequestValidationResult(_validatedAuthorizeRequest);

            _subject = new Saml2SingleSignOnEndpoint(
                _mockUserSession,
                _fakeLogger,
                _stubSigninResponseGenerator,
                _stubInteractionGenerator,
                _stubSignInRequestValidator,
                _mockUserConsentResponseMessageStore,
                _mockAuthorizationParametersMessageStore,
                _spOptions,
                _signoutGenerator,
                _fakeEventService,
                _serialzer);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signin_request_validation_produces_error_should_display_error_page()
        {
            _stubSignInRequestValidator.Result.IsError = true;
            _stubSignInRequestValidator.Result.Error = "some_error";

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        /*
        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_generator_consent_produces_consent_should_show_consent_page()
        {
            _stubInteractionGenerator.Response.IsConsent = true;

            var result = await _subject.ProcessSignInRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<IdentityServer4.Endpoints.Results.ConsentPageResult>();
        }
        */

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_error_should_show_error_page()
        {
            _stubInteractionGenerator.Response.Error = "error";

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_error_should_show_error_page_with_error_description_if_present()
        {
            var errorDescription = "some error description";

            _stubInteractionGenerator.Response.Error = "error";
            _stubInteractionGenerator.Response.ErrorDescription = errorDescription;

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
            var errorResult = (Endpoints.Results.ErrorPageResult)result;
            errorResult.ErrorDescription.Should().Be(errorDescription);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task interaction_produces_login_result_should_trigger_login()
        {
            _stubInteractionGenerator.Response.IsLogin = true;

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.LoginPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task custom_interaction_redirect_result_should_issue_redirect()
        {
            _mockUserSession.User = _user;
            _stubInteractionGenerator.Response.RedirectUrl = "http://foo.com";

            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.CustomRedirectResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task successful_signin_request_should_generate_signin_result()
        {
            var result = await _subject.ProcessAuthenticationRequestAsync(_signIn, _user, null);

            result.Should().BeOfType<Endpoints.Results.SignInResult>();
        }

        /*
        [Fact]
        [Trait("Category", Category)]
        public async Task signout_request_without_wtrealm_should_display_logout_page()
        {
            _signOut.Wtrealm = null;

            var result = await _subject.ProcessSignOutAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.LogoutPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task signout_request_without_wreply_should_display_logout_page()
        {
            _signOut.Wreply = null;

            var result = await _subject.ProcessSignOutAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.LogoutPageResult>();
        }
        */

        [Fact]
        [Trait("Category", Category)]
        public async Task signout_request_validation_produces_error_should_display_error_page()
        {
            _stubSignInRequestValidator.Result.IsError = true;
            _stubSignInRequestValidator.Result.Error = "some_error";

            var result = await _subject.ProcessSignOutAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.ErrorPageResult>();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task successful_authorization_request_should_generate_signout_result()
        {
            var result = await _subject.ProcessSignOutAsync(_signOut, _user);

            result.Should().BeOfType<Endpoints.Results.SignOutResult>();
        }
    }
}
