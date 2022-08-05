using Abc.IdentityServer4.Saml2.Services;
using IdentityServer4.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.Services
{
    internal class MockSaml2LogoutNotificationService : ISaml2LogoutNotificationService, ILogoutNotificationService
    {
        public bool GetFrontChannelLogoutNotificationsRequestsCalled { get; set; }
        public List<Saml2LogoutRequest> FrontChannelLogoutNotificationsRequests { get; set; } = new List<Saml2LogoutRequest>();

        public bool SendBackChannelLogoutNotificationsCalled { get; set; }
        public List<BackChannelLogoutRequest> BackChannelLogoutRequests { get; set; } = new List<BackChannelLogoutRequest>();

        public bool GetFrontChannelLogoutNotificationsUrlsCalled { get; set; }
        public List<string> FrontChannelLogoutNotificationsUrls { get; set; } = new List<string>();

        public Task<IEnumerable<string>> GetFrontChannelLogoutNotificationsUrlsAsync(LogoutNotificationContext context)
        {
            GetFrontChannelLogoutNotificationsUrlsCalled = true;
            return Task.FromResult(FrontChannelLogoutNotificationsUrls.AsEnumerable());
        }

        public Task<IEnumerable<BackChannelLogoutRequest>> GetBackChannelLogoutNotificationsAsync(LogoutNotificationContext context)
        {
            SendBackChannelLogoutNotificationsCalled = true;
            return Task.FromResult(BackChannelLogoutRequests.AsEnumerable());
        }

        public Task<IEnumerable<Saml2LogoutRequest>> GetFrontChannelLogoutNotificationsRequestsAsync(LogoutNotificationContext context)
        {
            GetFrontChannelLogoutNotificationsRequestsCalled = true;
            return Task.FromResult(FrontChannelLogoutNotificationsRequests.AsEnumerable());
        }
    }
}
