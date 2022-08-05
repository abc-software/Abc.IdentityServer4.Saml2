using FluentAssertions;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Services.UnitTests
{
    public class Saml2IdentityServerInteractionServiceFixture
    {
        private Saml2IdentityServerInteractionService _target;

        private IdentityServerOptions _options = new IdentityServerOptions();
        private MockHttpContextAccessor _mockHttpContextAccessor;
        private MockMessageStore<LogoutNotificationContext> _mockEndSessionStore = new MockMessageStore<LogoutNotificationContext>();
        private MockMessageStore<LogoutMessage> _mockLogoutMessageStore = new MockMessageStore<LogoutMessage>();
        private MockUserSession _mockUserSession = new MockUserSession();
        private IIdentityServerInteractionService _identityServerIteraction = new StubIdentityServerInteractionService();

        public Saml2IdentityServerInteractionServiceFixture()
        {
            _mockHttpContextAccessor = new MockHttpContextAccessor(_options, _mockUserSession, _mockEndSessionStore);

            _target = new Saml2IdentityServerInteractionService(_identityServerIteraction, _mockHttpContextAccessor, _mockLogoutMessageStore);
        }

        [Fact]
        public async Task GetLogoutContextAsync_valid_session_and_logout_id_should_not_provide_signout_iframe()
        {
            // for this, we're just confirming that since the session has changed, there's not use in doing the iframe and thsu SLO
            _mockUserSession.SessionId = null;
            _mockLogoutMessageStore.Messages.Add("id", new Message<LogoutMessage>(new LogoutMessage() { SessionId = "session" }, DateTime.UtcNow));

            var context = await _target.GetLogoutContextAsync("id");

            context.SignOutIFrameUrl.Should().BeNull();
        }

        [Fact]
        public async Task GetLogoutContextAsync_valid_session_no_logout_id_should_provide_iframe()
        {
            _mockUserSession.Clients.Add("foo");
            _mockUserSession.SessionId = "session";
            _mockUserSession.User = new IdentityServerUser("123").CreatePrincipal();

            var context = await _target.GetLogoutContextAsync(null);

            context.SignOutIFrameUrl.Should().NotBeNull();
            context.SignOutIFrameUrl.Should().Contain("saml2/slo/callback?endSessionId=");
        }

        [Fact]
        public async Task GetLogoutContextAsync_without_session_should_not_provide_iframe()
        {
            _mockUserSession.SessionId = null;
            _mockLogoutMessageStore.Messages.Add("id", new Message<LogoutMessage>(new LogoutMessage(), DateTime.UtcNow));

            var context = await _target.GetLogoutContextAsync("id");

            context.SignOutIFrameUrl.Should().BeNull();
        }
    }
}
