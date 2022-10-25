using Abc.IdentityModel.Protocols.Saml2;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using Xunit;

namespace Abc.IdentityServer4.Saml2.UnitTests
{
    public class Saml2RequestExtnesionsFixture
    {
        private readonly Saml2RequestedAuthenticationContext authenticationContext;
        private Saml2AuthenticationRequest request;

        public Saml2RequestExtnesionsFixture()
        {
            authenticationContext = new Saml2RequestedAuthenticationContext()
            {
                ReferenceType = Saml2AuthenticationContextReferenceType.Class,
            };

            authenticationContext.References.Add("idp:test".ToUri()); // idp
            authenticationContext.References.Add("tenant:t1".ToUri()); // tenant
            authenticationContext.References.Add("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".ToUri()); // acr
            authenticationContext.References.Add("key".ToUri()); // acr short

            request = new Saml2AuthenticationRequest()
            {
                RequestedAuthenticationContext = authenticationContext,
            };
        }

        [Fact]
        public void invalid_saml2_message_should_return_null_idp()
        {
            var request = new Saml2LogoutRequest(new Saml2NameIdentifier("urn:issuer"));
            request.GetIdP().Should().BeNull();
        }

        [Fact]
        public void saml2_message_without_authcontext_should_return_null_idp()
        {
            request.RequestedAuthenticationContext = null;
            request.GetIdP().Should().BeNull();
        }

        [Fact]
        public void saml2_message_authdeclr_should_return_null_idp()
        {
            request.RequestedAuthenticationContext.ReferenceType = Saml2AuthenticationContextReferenceType.Declaration;
            request.GetIdP().Should().BeNull();
        }

        [Fact]
        public void saml2_message_should_return_idp()
        {
            request.GetIdP().Should().Be("test");
        }

        [Fact]
        public void saml2_message_should_return_tenant()
        {
            request.GetTenant().Should().Be("t1");
        }

        [Fact]
        public void saml2_message_should_return_acr()
        {
            request.GetAcrValues().Should().HaveCount(2);
            request.GetAcrValues().Should().Contain("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
            request.GetAcrValues().Should().Contain("key");
        }

        [Fact]
        public void saml2_message_remove_idp()
        {
            request.RemoveIdP();

            request.GetIdP().Should().BeNull();
        }

        [Fact]
        public void saml2_message_remove_tenant()
        {
            request.RemoveTenant();

            request.GetTenant().Should().BeNull();
        }

        [Fact]
        public void saml2_message_remove_acr()
        {
            request.RemoveAcrValue("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".ToUri());

            request.GetAcrValues().Should().ContainSingle("key");
        }
    }
}
