using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing.UnitTests
{
    public class SignInInteractionResponseGeneratorFixture
    {
        private readonly IdentityServerOptions _options = new IdentityServerOptions();
        private readonly SignInInteractionResponseGenerator _subject;
        private readonly StubClock _clock = new StubClock();

        public SignInInteractionResponseGeneratorFixture()
        {
            _subject = new SignInInteractionResponseGenerator(
                _clock,
                TestLogger.Create<SignInInteractionResponseGenerator>());
        }

        [Fact]
        public async Task Invalid_validated_saml2_request()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = Principal.Anonymous,
            };

            Func<Task> act = () => _subject.ProcessInteractionAsync(request);

            await act.Should().ThrowAsync<InvalidOperationException>();
        }

        [Fact]
        public async Task Anonymous_User_must_SignIn()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = Principal.Anonymous,
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()), 
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_must_not_SignIn()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                ValidatedResources = new ResourceValidationResult(),
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client(),
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_allowed_current_Idp_must_not_SignIn()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client
                {
                    IdentityProviderRestrictions = new List<string>
                    {
                        IdentityServerConstants.LocalIdentityProvider,
                    },
                },
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_restricted_current_Idp_must_SignIn()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client
                {
                    EnableLocalLogin = false,
                    IdentityProviderRestrictions = new List<string>
                    {
                        "some_idp",
                    },
                },
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_with_allowed_requested_Idp_must_not_SignIn()
        {
            var authenticationContext = new Saml2RequestedAuthenticationContext();
            authenticationContext.ReferenceType = Saml2AuthenticationContextReferenceType.Class;
            authenticationContext.References.Add(new Uri("idp:" + IdentityServerConstants.LocalIdentityProvider));

            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()
                {
                    RequestedAuthenticationContext = authenticationContext,
                }),
                Client = new Client(),
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_with_different_requested_Idp_must_SignIn()
        {
            var authenticationContext = new Saml2RequestedAuthenticationContext();
            authenticationContext.ReferenceType = Saml2AuthenticationContextReferenceType.Class;
            authenticationContext.References.Add(new Uri("idp:some_idp"));

            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()
                {
                    RequestedAuthenticationContext = authenticationContext,
                }),
                Client = new Client(),
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task Authenticated_User_within_client_user_sso_lifetime_should_not_signin()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = "local",
                    AuthenticationTime = _clock.UtcNow.UtcDateTime.Subtract(TimeSpan.FromSeconds(10)),
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client()
                {
                    UserSsoLifetime = 3600, // 1h
                },
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeFalse();
        }

        [Fact]
        public async Task Authenticated_User_beyond_client_user_sso_lifetime_should_signin()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = "local",
                    AuthenticationTime = _clock.UtcNow.UtcDateTime.Subtract(TimeSpan.FromSeconds(3700)),
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client()
                {
                    UserSsoLifetime = 3600, // 1h
                },
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task locally_authenticated_user_but_client_does_not_allow_local_should_sign_in()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123")
                {
                    IdentityProvider = IdentityServerConstants.LocalIdentityProvider,
                }.CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest()),
                Client = new Client()
                {
                    EnableLocalLogin = false,
                },
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
        }

        [Fact]
        public async Task prompt_login_should_sign_in()
        {
            var request = new ValidatedSaml2Request
            {
                ClientId = "foo",
                Subject = new IdentityServerUser("123").CreatePrincipal(),
                Saml2RequestMessage = new HttpSaml2RequestMessage2(new Uri("https://server/saml2"), new Saml2AuthenticationRequest() {
                    ForceAuthentication = true,
                }),
            };

            var result = await _subject.ProcessInteractionAsync(request);

            result.IsLogin.Should().BeTrue();
            (request.Saml2RequestMessage.Saml2Request as Saml2AuthenticationRequest).ForceAuthentication.Should().BeFalse();
        }
    }
}