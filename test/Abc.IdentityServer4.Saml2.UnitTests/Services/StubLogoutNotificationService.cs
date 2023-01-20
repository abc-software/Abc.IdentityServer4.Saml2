using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services.UnitTests
{
    internal class StubLogoutNotificationService : ILogoutNotificationService
    {
        public List<BackChannelLogoutRequest> BackChannelLogoutNotification { get; } = new List<BackChannelLogoutRequest>();
        public List<string> FrontChannelLogoutNotificationsUrls { get; } = new List<string>();

        public Task<IEnumerable<BackChannelLogoutRequest>> GetBackChannelLogoutNotificationsAsync(LogoutNotificationContext context)
        {
            return Task.FromResult<IEnumerable<BackChannelLogoutRequest>>(BackChannelLogoutNotification);
        }

        public Task<IEnumerable<string>> GetFrontChannelLogoutNotificationsUrlsAsync(LogoutNotificationContext context)
        {
            return Task.FromResult<IEnumerable<string>>(FrontChannelLogoutNotificationsUrls);
        }
    }
}