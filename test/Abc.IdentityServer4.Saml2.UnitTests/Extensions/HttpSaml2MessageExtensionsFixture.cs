using Abc.IdentityModel.Protocols.Saml2;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Saml2LogoutRequest = Abc.IdentityModel.Protocols.Saml2.Saml2LogoutRequest;

namespace Abc.IdentityServer4.Saml2.UnitTests
{
    public class HttpSaml2MessageExtensionsFixture
    {
        [Fact]
        public void serilaize_valid_saml2_message()
        {
            var signOut = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("urn:issuer"))) {  RelayState = "relayState" };

            var dictionary = signOut.ToDictionary();
            dictionary.Keys.Should().Contain("SAMLRequest");
            dictionary.Keys.Should().Contain("RelayState");
        }

        [Fact]
        public void serilaize_null_saml2_should_return_empty()
        {
            var signOut = (HttpSaml2RequestMessage2)null;

            var dictionary = signOut.ToDictionary();
            dictionary.Should().BeEmpty();
        }

        [Fact]
        public void deserilaize_null_dictionary_should_return_null()
        {
            var entity = (Dictionary<string, string[]>)null;

            var message = entity.ToSaml2Message();
            message.Should().BeNull();
        }

        [Fact]
        public void deserilaize_empty_dictionary_should_return_null()
        {
            var entity = new Dictionary<string, string[]>();

            var message = entity.ToSaml2Message();
            message.Should().BeNull();
        }

        [Fact]
        public void deserilaize_valid_dictionary()
        {
            var signOut = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2LogoutRequest(new Saml2NameIdentifier("urn:issuer"))) { RelayState = "relayState" };
            var entity = signOut.ToDictionary();

            var message = entity.ToSaml2Message();
            message.Should().NotBeNull();
            message.RelayState.Should().Be("relayState");
        }
    }
}
