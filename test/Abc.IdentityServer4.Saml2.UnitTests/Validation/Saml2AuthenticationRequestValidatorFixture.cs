using Abc.IdentityModel.Protocols.Saml2;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Validation.UnitTests
{
    public class Saml2AuthenticationRequestValidatorFixture : Saml2RequestValidatorBase
    {
        [Fact]
        public async Task Valid_request()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().Be(false);
        }

        [Fact]
        public async Task Valid_request_with_all_paramters()
        {
            var authenticationContext = new Saml2RequestedAuthenticationContext();
            authenticationContext.ReferenceType = Saml2AuthenticationContextReferenceType.Class;
            authenticationContext.References.Add("idp:local".ToUri());

            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                AssertionConsumerServiceUrl = "https://wsfed/callback".ToUri(),
                IssueInstant = clock.UtcNow.UtcDateTime,
                RequestedAuthenticationContext = authenticationContext,
            })
            {
                RelayState = "realyState",
            };

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().Be(false);
        }

        [Fact]
        public void Null_Parameter()
        {
            Func<Task> act = () => validator.ValidateAsync(null, null);
            act.Should().ThrowAsync<ArgumentNullException>();
        }

        [Fact]
        public async Task Empty_Parameters()
        {
            var result = await validator.ValidateAsync(new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), "some_request"), null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Missing_Issuer()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_Protocol_Client()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("codeclient"),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_relying_party");
        }

        [Fact]
        public async Task Malformed_AssertionConsumerServiceUrl()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                AssertionConsumerServiceUrl = "/callback".ToUri(),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Ignore_Invalid_AssertionConsumerServiceUrl()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                AssertionConsumerServiceUrl = "https://host/reply".ToUri(),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeFalse();
        }

        [Fact]
        public async Task Invalid_IssueInstant_in_funture()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                IssueInstant = clock.UtcNow.UtcDateTime.AddHours(1),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_IssueInstant_in_past()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                IssueInstant = clock.UtcNow.UtcDateTime.AddHours(-1),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_Conditions_NotOnOrAfter()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                Conditions = new Saml2Conditions() { NotOnOrAfter = clock.UtcNow.UtcDateTime.AddHours(-1) },
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_Conditions_NotBefore()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                Conditions = new Saml2Conditions() { NotBefore = clock.UtcNow.UtcDateTime.AddHours(1) },
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

    }
}