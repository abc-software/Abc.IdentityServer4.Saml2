using Abc.IdentityServer4.Saml2.Stores;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using MockUserSession = IdentityServer4.Services.MockUserSession;

namespace Abc.IdentityServer4.Saml2.Validation.UnitTests
{
    public abstract class Saml2RequestValidatorBase
    {
        protected readonly Saml2RequestValidator validator;
        protected readonly ISystemClock clock;

        public Saml2RequestValidatorBase()
        {
            var options = TestIdentityServerOptions.Create();
            var relayingPartyStore = new InMemoryRelyingPartyStore(new []
            {
                new RelyingParty
                {
                    EntityId = "urn:test",
                }
            });
            var clients = new InMemoryClientStore(new[]
            {
                  new Client
                    {
                        ClientId = "urn:test",
                        ClientName = "SAML2 Client",
                        ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                        Enabled = true,
                        RedirectUris = { "https://saml2/callback" },
                        FrontChannelLogoutUri = "https://saml2/signout",
                    },
                    new Client
                    {
                        ClientName = "Code Client",
                        Enabled = true,
                        ClientId = "codeclient",
                    },
                });

                var uriValidator = new StrictRedirectUriValidator();

            var userSession = new MockUserSession();

            clock = new StubClock();
            validator = new Saml2RequestValidator(
                TestLogger.Create<Saml2RequestValidator>(),
                clients,
                userSession,
                uriValidator,
                options,
                clock,
                relayingPartyStore
                );
        }
     }
}