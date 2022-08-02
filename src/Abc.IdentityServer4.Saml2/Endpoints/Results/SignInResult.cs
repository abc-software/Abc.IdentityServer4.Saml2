using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    public class SignInResult : IEndpointResult
    {
        private IdentityServerOptions _options;
        private HttpSaml2MessageSerializer _serializer;

        public HttpSaml2Message2 Message { get; set; }

        public SignInResult(HttpSaml2Message2 message)
        {
            Message = message ?? throw new System.ArgumentNullException(nameof(message));
        }

        internal SignInResult(HttpSaml2Message2 message, HttpSaml2MessageSerializer serializer, IdentityServerOptions options)
            : this(message)
        {
            _serializer = serializer;
            _options = options;
        }

        public async Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            await _serializer.SendMessageAsync(context.Response, Message);

            // serializer do not add CSP header to post form
            if (context.Response.ContentType != null && context.Response.ContentType.Contains("text/html"))
            {
                context.Response.AddFormPostCspHeaders(_options.Csp, Message.BaseUri.AbsoluteUri.GetOrigin(), "sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec=");
            }
        }

        private void Init(HttpContext context)
        {
            _serializer ??= context.RequestServices.GetRequiredService<HttpSaml2MessageSerializer>();
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
        }
    }
}