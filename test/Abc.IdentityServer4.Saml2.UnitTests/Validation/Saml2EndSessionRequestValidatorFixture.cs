using FluentAssertions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using System;
using System.Collections.Specialized;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Validation.UnitTests
{
    public class Saml2EndSessionRequestValidatorFixture
    {
        private Saml2EndSessionRequestValidator _target;

        private MockSaml2LogoutNotificationService _mockLogoutNotificationService = new MockSaml2LogoutNotificationService();
        private MockMessageStore<LogoutNotificationContext> _mockEndSessionMessageStore = new MockMessageStore<LogoutNotificationContext>();

        public Saml2EndSessionRequestValidatorFixture()
        {
            _target = new Saml2EndSessionRequestValidator(
                _mockLogoutNotificationService,
                _mockEndSessionMessageStore,
                TestLogger.Create<Saml2EndSessionRequestValidator>()
                );
        }

        [Fact]
        public async Task valid_params_should_return_success()
        {
            _mockEndSessionMessageStore.Messages.Add("123", new Message<LogoutNotificationContext>(new LogoutNotificationContext() { ClientIds = new string[] { "session" } }, DateTime.Now));
            _mockLogoutNotificationService.FrontChannelLogoutNotificationsRequests.Add(new Services.Saml2LogoutRequest("", "", ""));

            var parameters = new NameValueCollection();
            parameters.Add("endSessionId", "123");

            var result = await _target.ValidateCallbackAsync(parameters);
            result.IsError.Should().BeFalse();
            result.FrontChannelLogoutRequests.Should().NotBeEmpty();

            _mockLogoutNotificationService.GetFrontChannelLogoutNotificationsRequestsCalled.Should().BeTrue();
        }

        [Fact]
        public async Task session_without_clients_should_return_error()
        {
            _mockEndSessionMessageStore.Messages.Add("123", new Message<LogoutNotificationContext>(new LogoutNotificationContext(), DateTime.Now));
            _mockLogoutNotificationService.BackChannelLogoutRequests.Add(new BackChannelLogoutRequest());

            var parameters = new NameValueCollection();
            parameters.Add("endSessionId", "123");

            var result = await _target.ValidateCallbackAsync(parameters);
            result.IsError.Should().BeTrue();
        }

        [Fact]
        public async Task invalid_session_should_return_error()
        {
            var parameters = new NameValueCollection();
            parameters.Add("endSessionId", "123");

            var result = await _target.ValidateCallbackAsync(parameters);
            result.IsError.Should().BeTrue();
        }

        [Fact]
        public async Task invalid_params_should_return_error()
        {
            var parameters = new NameValueCollection();

            var result = await _target.ValidateCallbackAsync(parameters);

            result.IsError.Should().BeTrue();
        }
    }
}
