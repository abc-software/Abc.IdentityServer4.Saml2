using FluentAssertions;
using Xunit;
using System;
using System.Threading.Tasks;
using Abc.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Abc.IdentityServer4.Saml2.Validation.UnitTests
{
    public class Saml2LogoutRequestValidatorFixture : Saml2RequestValidatorBase
    {
        [Fact]
        public async Task Valid_request()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().Be(false);
        }

        //[Fact]
        //public async Task Valid_request_with_all_paramters()
        //{
        //    var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("urn:test"))
        //    {
                
        //    });

        //    var message = new WsFederationMessage()
        //    {
        //        Wa = "wsignout1.0",
        //        Wtrealm = "urn:test",
        //        Wreply = "https://wsfed/postlogout",
        //        Wctx = "context",
        //        Wct = clock.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        //    };

        //    var result = await validator.ValidateAsync(message, null);

        //    result.IsError.Should().Be(false);
        //}

        [Fact]
        public void Null_Parameter()
        {
            Func<Task> act = () => validator.ValidateAsync(null, null);
            act.Should().ThrowAsync<ArgumentNullException>();
        }

        [Fact]
        public async Task Empty_Parameters()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), "some_request");

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Missing_Issuer()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
            {
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_Protocol_Client()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
            {
                Issuer = new Saml2NameIdentifier("codeclient"),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_relying_party");
        }

        [Fact]
        public async Task Invalid_IssueInstant_in_funture()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
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
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                IssueInstant = clock.UtcNow.UtcDateTime.AddHours(-1),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }

        [Fact]
        public async Task Invalid_NotOnOrAfter()
        {
            var message = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("sub"))
            {
                Issuer = new Saml2NameIdentifier("urn:test"),
                NotOnOrAfter = clock.UtcNow.UtcDateTime.AddHours(-1),
            });

            var result = await validator.ValidateAsync(message, null);

            result.IsError.Should().BeTrue();
            result.Error.Should().Be("invalid_request");
        }
    }
}