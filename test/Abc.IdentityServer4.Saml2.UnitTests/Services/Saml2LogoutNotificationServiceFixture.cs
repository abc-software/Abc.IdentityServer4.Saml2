using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Endpoints.UnitTests;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Services;
using Abc.IdentityServer4.Saml2.Stores;
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
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Services.UnitTests
{
    public class Saml2LogoutNotificationServiceFixture
    {
        private readonly Saml2LogoutNotificationService _subject;
        private StubLogoutRequestGenerator _requestGenerator;
        private InMemoryRelyingPartyStore _relyingPartyStore;
        private StubLogoutNotificationService _logoutNotificationService;
        private IClientStore _clientStore;

        public Saml2LogoutNotificationServiceFixture()
        {
            var relyingParties = new RelyingParty[]
            {
                new RelyingParty()
                {
                    EntityId = "urn:client1",
                    FrontChannelLogoutBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 
                },
                new RelyingParty()
                {
                    EntityId = "urn:client2",
                    FrontChannelLogoutBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            };

            var clients = new Client[]
            {
                new Client()
                {
                    ClientId = "urn:client1",
                    ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                    FrontChannelLogoutUri = "https://client2/signout",
                },
                new Client()
                {
                    ClientId = "urn:client2",
                    ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                    FrontChannelLogoutUri = "https://client2/signout",
                },
                new Client()
                {
                    ClientId = "urn:client5",
                    ProtocolType = IdentityServerConstants.ProtocolTypes.Saml2p,
                    FrontChannelLogoutUri = "https://client5/signout",
                },
            };

            _relyingPartyStore = new InMemoryRelyingPartyStore(relyingParties);
            _clientStore = new InMemoryClientStore(clients);
            _logoutNotificationService = new StubLogoutNotificationService();
            _requestGenerator = new StubLogoutRequestGenerator();

            _subject = new Saml2LogoutNotificationService(
               _logoutNotificationService,
               _relyingPartyStore,
               _clientStore,
               _requestGenerator,
               new HttpSaml2MessageSerializer(null),
               TestLogger.Create<Saml2LogoutNotificationService>()
                );
        }

        [Fact]
        public async Task front_channel_should_return_empty_if_no_clients()
        {
            var context = new LogoutNotificationContext()
            {
                SessionId = "session",
            };

            _logoutNotificationService.FrontChannelLogoutNotificationsUrls.Add("https://client1/signout");

            var request = await _subject.GetFrontChannelLogoutNotificationsRequestsAsync(context);

            request.Should().BeEmpty();
        }

        [Fact]
        public async Task front_channel_should_return_oidc_logout_notificatoins_as_redirect()
        {
            var context = new LogoutNotificationContext()
            {
                SessionId = "session",
                ClientIds = new[] { "urn:client3" },
            };

            _logoutNotificationService.FrontChannelLogoutNotificationsUrls.Add("https://client3/signout");

            var request = await _subject.GetFrontChannelLogoutNotificationsRequestsAsync(context);

            request.Should().HaveCount(1);
            request.Should().ContainEquivalentOf(new Saml2LogoutRequest("https://client3/signout", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://client3"));
        }

        [Fact]
        public async Task front_channel_should_return_saml2_logout_notificatoins_as_redirect()
        {
            var context = new LogoutNotificationContext()
            {
                SessionId = "session",
                ClientIds = new[] { "urn:client1;urn:ivis:100001:name.id-viss;;;;_60b25154-ef6c-49d1-8b20-90a2a70e4bc9" },
                SubjectId = "bob",
            };

            _requestGenerator.Message = new HttpSaml2RequestMessage2("https://client1/signout".ToUri(), "some_response");

            var request = await _subject.GetFrontChannelLogoutNotificationsRequestsAsync(context);

            request.Should().HaveCount(1);
            request.Should().ContainEquivalentOf(new Saml2LogoutRequest("https://client1/signout?SAMLRequest=some_response", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "https://client1"));
        }

        [Fact]
        public async Task front_channel_should_return_saml2_logout_notificatoins_as_post()
        {
            var context = new LogoutNotificationContext()
            {
                SessionId = "session",
                ClientIds = new[] { "urn:client2;urn:ivis:100001:name.id-viss;;;;_60b25154-ef6c-49d1-8b20-90a2a70e4bc9" },
                SubjectId = "bob",
            };

            _requestGenerator.Message = new HttpSaml2RequestMessage2("https://client2/signout".ToUri(), "some_response", IdentityModel.Http.HttpDeliveryMethods.PostRequest);

            var request = await _subject.GetFrontChannelLogoutNotificationsRequestsAsync(context);

            var expectedPostForm = "<form class=\"load\" method=\"POST\" name=\"hiddenform\" action=\"https://client2/signout\"><input type=\"hidden\" name=\"SAMLRequest\" value=\"some_response\" /><noscript><p>Script is disabled. Click Submit to continue.</p><input type=\"submit\" value=\"Submit\" /></noscript></form>";

            request.Should().HaveCount(1);
            request.Should().ContainEquivalentOf(new Saml2LogoutRequest(expectedPostForm, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "https://client2"));
        }

    }
}
