using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    internal class LogoutPageResult : IEndpointResult
    {
        private readonly string requestId;
        private readonly string logoutId;
        private IdentityServerOptions options;

        public LogoutPageResult(string requestId, string logoutId)
        {
            this.requestId = requestId;
            this.logoutId = logoutId;
        }

        internal LogoutPageResult(IdentityServerOptions options)
        {
            this.options = options;
        }

        public Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            var redirectUrl = options.UserInteraction.LogoutUrl;
            
            if (logoutId != null)
            {
                redirectUrl = redirectUrl.AddQueryString(options.UserInteraction.LogoutIdParameter, logoutId);
            }
            
            //if (!string.IsNullOrWhiteSpace(requestId))
            //{
            //    redirectUrl = redirectUrl.AddQueryString(samlOptions.UserInteraction.RequestIdParameter, RequestId);
            //}

            context.Response.RedirectToAbsoluteUrl(redirectUrl);
            return Task.CompletedTask;
        }

        private void Init(HttpContext context)
        {
            options = options ?? context.RequestServices.GetRequiredService<IdentityServerOptions>();
        }
    }
}
