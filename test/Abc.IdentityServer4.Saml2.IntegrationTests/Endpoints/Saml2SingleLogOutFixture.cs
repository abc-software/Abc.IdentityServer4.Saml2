using Abc.IdentityServer4.Saml2.IntegrationTests.Common;
using Abc.IdentityServer4.Saml2.Stores;
using FluentAssertions;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Xunit;
using static IdentityServer4.IdentityServerConstants;

namespace Abc.IdentityServer4.Saml2.Endpoints.IntegrationTests
{
    public class Saml2SingleLogOutFixture {
        private const string Category = "SAML2 single sign-on endpoint";

        private IdentityServerPipeline _mockPipeline = new IdentityServerPipeline();
        private Client _wsfedClient;

        public Saml2SingleLogOutFixture()
        {
            _mockPipeline.Clients.Add(new Client
            {
                ClientId = "urn:client1",
                RequireConsent = false,
                ProtocolType = "saml2p",
                AllowedScopes = new List<string> { "saml2_client" },
                RedirectUris = new List<string> { "https://client1/callback" },
                FrontChannelLogoutUri = "https://client1/signout",
                PostLogoutRedirectUris = new List<string> { "https://client1/signout-callback" },
                AllowAccessTokensViaBrowser = true
            });

            _mockPipeline.Clients.Add(new Client
            {
                ClientId = "urn:client2",
                RequireConsent = false,
                ProtocolType = "saml2p",
                AllowedScopes = new List<string> { "saml2_client" },
                RedirectUris = new List<string> { "https://client2/callback" },
                FrontChannelLogoutUri = "https://client2/signout",
                PostLogoutRedirectUris = new List<string> {
                    "https://client2/signout-callback",
                    "https://client2/signout-callback2"
                },
                AllowAccessTokensViaBrowser = true
            });

            _mockPipeline.Clients.Add(new Client
            {
                ClientId = "urn:client3",
                AllowedGrantTypes = GrantTypes.Implicit,
                RequireConsent = false,
                AllowedScopes = new List<string> { "openid" },
                RedirectUris = new List<string> { "https://client3/callback" },
                FrontChannelLogoutUri = "https://client3/signout",
                AllowAccessTokensViaBrowser = true
            });

            _mockPipeline.Clients.Add(_wsfedClient = new Client
            {
                ClientId = "urn:client4",
                AllowedGrantTypes = GrantTypes.Implicit,
                RequireConsent = false,
                AllowedScopes = new List<string> { "openid" },
                RedirectUris = new List<string> { "https://client4/callback" },
                FrontChannelLogoutUri = "https://client4/signout",
                AllowAccessTokensViaBrowser = true
            });

            _mockPipeline.Clients.Add(new Client
            {
                ClientId = "urn:client5",
                RequireConsent = false,
                ProtocolType = "saml2p",
                AllowedScopes = new List<string> { "saml2_client" },
                RedirectUris = new List<string> { "https://client5/callback" },
                FrontChannelLogoutUri = "https://client5/signout",
                PostLogoutRedirectUris = new List<string> { "https://client5/signout-callback" },
                AllowAccessTokensViaBrowser = true
            });

            _mockPipeline.Users.Add(new TestUser
            {
                SubjectId = "bob",
                Username = "bob",
                Claims = new Claim[]
                {
                    new Claim("name", "Bob Loblaw"),
                    new Claim("email", "bob@loblaw.com"),
                    new Claim("role", "Attorney")
                }
            });

            _mockPipeline.IdentityScopes.AddRange(new IdentityResource[] {
                new IdentityResources.OpenId(),
                new IdentityResource() { Name = "saml2_client", UserClaims = new string[] { "name", "email" } },
            });

            /*
            _mockPipeline.OnPostConfigureServices += (s) =>
            {
                var relyingParties = new List<RelyingParty>();

                foreach (var client in _mockPipeline.Clients.Where(x => x.ProtocolType == ProtocolTypes.Saml2p)) {
                    var relyingParty = new RelyingParty()
                    {
                        EntityId = client.ClientId,
                    };

                    if(client.FrontChannelLogoutUri != null)
                    {
                        relyingParty.SingleLogoutService = new Service() { Location = client.FrontChannelLogoutUri, Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" };
                    }

                    relyingParties.Add(relyingParty);
                }

                s.AddSingleton<IRelyingPartyStore>(s => new InMemoryRelyingPartyStore(relyingParties));
            };
            */

            _mockPipeline.Initialize();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_request_should_redirect_to_logout_page()
        {
            var url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client1",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: null);

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_request_should_redirect_to_configured_logout_path()
        {
            _mockPipeline.Options.UserInteraction.LogoutUrl = "/logout";
            _mockPipeline.Options.UserInteraction.LogoutIdParameter = "id";

            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client1",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url); 

            response.StatusCode.Should().Be(HttpStatusCode.Redirect);
            response.Headers.Location.ToString().Should().StartWith("https://server/logout?id=");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_request_should_pass_values_in_logout_context_many_clients()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var url1 = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");

            var response1 = await _mockPipeline.BrowserClient.GetAsync(url1);


            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client2",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url); 

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
            _mockPipeline.LogoutRequest.Should().NotBeNull();
            _mockPipeline.LogoutRequest.ClientId.Should().Be("urn:client2");
            {
                var parts = _mockPipeline.LogoutRequest.PostLogoutRedirectUri.Split('?');
                parts[0].Should().Be(IdentityServerPipeline.Saml2SingleLogOutCallbackEndpoint);
                var iframeUrl = QueryHelpers.ParseNullableQuery(parts[1]);
                iframeUrl["requestId"].FirstOrDefault().Should().NotBeNull();
            }

            {
                var parts = _mockPipeline.LogoutRequest.SignOutIFrameUrl.Split('?');
                parts[0].Should().Be(IdentityServerPipeline.Saml2EndSessionCallbackEndpoint);
                var iframeUrl = QueryHelpers.ParseNullableQuery(parts[1]);
                iframeUrl["endSessionId"].FirstOrDefault().Should().NotBeNull();
            }
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_request_should_pass_values_in_logout_context_one_client()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client2",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url);

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
            _mockPipeline.LogoutRequest.Should().NotBeNull();
            _mockPipeline.LogoutRequest.ClientId.Should().Be("urn:client2");

            var parts = _mockPipeline.LogoutRequest.PostLogoutRedirectUri.Split('?');
            parts[0].Should().Be(IdentityServerPipeline.Saml2SingleLogOutCallbackEndpoint);
            var iframeUrl = QueryHelpers.ParseNullableQuery(parts[1]);
            iframeUrl["requestId"].FirstOrDefault().Should().NotBeNull();

            _mockPipeline.LogoutRequest.SignOutIFrameUrl.Should().BeNull();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_request_should_support_POST()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            var content  = _mockPipeline.CreateLogotPost(clientId: "urn:client2",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: authorization.SessionIndex);
            response = await _mockPipeline.BrowserClient.PostAsync(IdentityServerPipeline.Saml2SingleSignOnEndpoint, content);

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
            _mockPipeline.LogoutRequest.Should().NotBeNull();
            _mockPipeline.LogoutRequest.ClientId.Should().Be("urn:client2");

            var parts = _mockPipeline.LogoutRequest.PostLogoutRedirectUri.Split('?');
            parts[0].Should().Be(IdentityServerPipeline.Saml2SingleLogOutCallbackEndpoint);
            var iframeUrl = QueryHelpers.ParseNullableQuery(parts[1]);
            iframeUrl["requestId"].FirstOrDefault().Should().NotBeNull();

            _mockPipeline.LogoutRequest.SignOutIFrameUrl.Should().BeNull();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_endsession_callback_without_params_should_return_200()
        {
            var response = await _mockPipeline.BackChannelClient.GetAsync(IdentityServerPipeline.Saml2EndSessionCallbackEndpoint);

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task valid_signout_callback_should_return_200_html()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            var url2 = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");
            var response2 = await _mockPipeline.BrowserClient.GetAsync(url2);

            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            url = _mockPipeline.CreateLogoutUrl(
                           clientId: "urn:client1",
                           subjectId: "bob",
                           state: "123_state",
                           sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url);

            var signoutFrameUrl = _mockPipeline.LogoutRequest.SignOutIFrameUrl;

            response = await _mockPipeline.BrowserClient.GetAsync(signoutFrameUrl);
            response.StatusCode.Should().Be(HttpStatusCode.OK);
            response.Content.Headers.ContentType.MediaType.Should().Be("text/html");

            var postLogoutRedirectUri = _mockPipeline.LogoutRequest.PostLogoutRedirectUri;
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task endsession_callback_should_render_iframes_for_all_clients_except_initiator()
        {
            await _mockPipeline.LoginAsync("bob");
            var sid = _mockPipeline.GetSessionCookie().Value;

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            var url2 = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");
            var response2 = await _mockPipeline.BrowserClient.GetAsync(url2);

            var url3 = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client5",
                redirectUri: "https://client5/callback",
                state: "123_state");
            var response3 = await _mockPipeline.BrowserClient.GetAsync(url3);

            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            url = _mockPipeline.CreateLogoutUrl(
                           clientId: "urn:client1",
                           subjectId: "bob",
                           state: "123_state",
                           sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url);

            var signoutFrameUrl = _mockPipeline.LogoutRequest.SignOutIFrameUrl;

            response = await _mockPipeline.BrowserClient.GetAsync(signoutFrameUrl);
            var html = await response.Content.ReadAsStringAsync();
            html.Should().Contain(HtmlEncoder.Default.Encode("https://client2/signout?SAMLRequest="));
            html.Should().Contain(HtmlEncoder.Default.Encode("https://client5/signout?SAMLRequest="));
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task endsession_callback_should_use_signoutcleanup_for_wsfed_client()
        {
            await _mockPipeline.LoginAsync("bob");
            var sid = _mockPipeline.GetSessionCookie().Value;

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var url0 = _mockPipeline.CreateAuthorizeUrl(
                clientId: "urn:client4",
                responseType: "id_token",
                scope: "openid",
                redirectUri: "https://client4/callback",
                state: "123_state",
                nonce: "123_nonce");
            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response0 = await _mockPipeline.BrowserClient.GetAsync(url0);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                           clientId: "urn:client1",
                           subjectId: "bob",
                           state: "123_state",
                           sessionIndex: authorization.SessionIndex);
            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            response = await _mockPipeline.BrowserClient.GetAsync(url);

            var signoutFrameUrl = _mockPipeline.LogoutRequest.SignOutIFrameUrl;

            // since we don't have real ws-fed, we used OIDC to signin, but fooling this
            // at signout to use ws-fed so we can test the iframe params
            _wsfedClient.ProtocolType = ProtocolTypes.WsFederation;

            response = await _mockPipeline.BrowserClient.GetAsync(signoutFrameUrl);

            var html = await response.Content.ReadAsStringAsync();
            html.Should().Contain("https://client4/signout?wa=wsignoutcleanup1.0");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task endsession_callback_should_use_signout_for_oidc_client()
        {
            await _mockPipeline.LoginAsync("bob");
            var sid = _mockPipeline.GetSessionCookie().Value;

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var url0 = _mockPipeline.CreateAuthorizeUrl(
                clientId: "urn:client3",
                responseType: "id_token",
                scope: "openid",
                redirectUri: "https://client3/callback",
                state: "123_state",
                nonce: "123_nonce");
            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var response0 = await _mockPipeline.BrowserClient.GetAsync(url0);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                           clientId: "urn:client1",
                           subjectId: "bob",
                           state: "123_state",
                           sessionIndex: authorization.SessionIndex);
            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            response = await _mockPipeline.BrowserClient.GetAsync(url);

            var signoutFrameUrl = _mockPipeline.LogoutRequest.SignOutIFrameUrl;

            response = await _mockPipeline.BrowserClient.GetAsync(signoutFrameUrl);

            var html = await response.Content.ReadAsStringAsync();
            html.Should().Contain(HtmlEncoder.Default.Encode("https://client3/signout?sid=" + sid + "&iss=" + UrlEncoder.Default.Encode("https://server")));
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_with_one_client_should_not_render_signout_callback_iframe()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client2",
                redirectUri: "https://client2/callback",
                state: "123_state");

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client2",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url);

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
            _mockPipeline.LogoutRequest.SignOutIFrameUrl.Should().BeNull();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logout_without_clients_should_not_render_signout_callback_iframe()
        {
            await _mockPipeline.LoginAsync("bob");

            var url = _mockPipeline.CreateLogoutUrl(
                clientId: "urn:client2",
                subjectId: "bob",
                state: "123_state",
                sessionIndex: null);

            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            _mockPipeline.LogoutWasCalled.Should().BeTrue();
            _mockPipeline.LogoutRequest.SignOutIFrameUrl.Should().BeNull();
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task logoutcallback_should_return_logout_response()
        {
            await _mockPipeline.LoginAsync("bob");

            _mockPipeline.BrowserClient.AllowAutoRedirect = false;
            var url = _mockPipeline.CreateLoginUrl(
                clientId: "urn:client1",
                redirectUri: "https://client1/callback",
                state: "123_state");
            var response = await _mockPipeline.BrowserClient.GetAsync(url);

            var authorization = new Saml2LoginResponse(await response.Content.ReadAsStringAsync());

            _mockPipeline.BrowserClient.AllowAutoRedirect = true;
            url = _mockPipeline.CreateLogoutUrl(
                           clientId: "urn:client1",
                           subjectId: "bob",
                           state: "123_state",
                           sessionIndex: authorization.SessionIndex);

            response = await _mockPipeline.BrowserClient.GetAsync(url);

            var postLogoutRedirectUrl = _mockPipeline.LogoutRequest.PostLogoutRedirectUri;
            response = await _mockPipeline.BrowserClient.GetAsync(postLogoutRedirectUrl);

            {
                var parts = response.RequestMessage.RequestUri.AbsoluteUri.Split('?');
                parts[0].Should().Be("https://client1/signout");
                var query = QueryHelpers.ParseNullableQuery(parts[1]);
                query["SAMLResponse"].FirstOrDefault().Should().NotBeNull();
                query["RelayState"].FirstOrDefault().Should().Be("123_state");
            }
        }
    }
}
