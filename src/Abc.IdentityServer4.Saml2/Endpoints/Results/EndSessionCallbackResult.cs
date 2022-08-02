using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    internal class EndSessionCallbackResult : IEndpointResult
    {
        private readonly EndSessionCallbackValidationResult _result;
        private IdentityServerOptions _options;

        public EndSessionCallbackResult(EndSessionCallbackValidationResult result)
        {
            _result = result ?? throw new ArgumentNullException(nameof(result));
        }

        internal EndSessionCallbackResult(EndSessionCallbackValidationResult result, IdentityServerOptions options)
             : this(result)
        {
            _options = options;
        }

        public Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            var nonce = GenerateNonce();

            context.Response.SetNoCache();
            AddCspHeaders(context, nonce);

            var html = GetHtml(nonce);
            return context.Response.WriteHtmlAsync(html);
        }

        private static string GenerateNonce()
        {
            var nonceBytes = new byte[18];
            using (var rnd = RandomNumberGenerator.Create())
            {
                rnd.GetBytes(nonceBytes);
            }

            return Base64UrlTextEncoder.Encode(nonceBytes);
        }

        private void Init(HttpContext context)
        {
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
        }

        private void AddCspHeaders(HttpContext context, string nonce)
        {
            if (_options.Authentication.RequireCspFrameSrcForSignout)
            {
                string frameSources = null;
                var origins = _result.FrontChannelLogoutRequests?.Select(x => x.Origin);
                if (origins != null && origins.Any())
                {
                    frameSources = origins.Distinct().Aggregate(new StringBuilder(), (sb, v) => sb.Append(v).Append(" "), sb => sb.ToString());
                }

                // the hash matches the embedded style element being used below
                context.Response.AddFormPostCspHeaders(_options.Csp, "sha256-e6FQZewefmod2S/5T11pTXjzE2vn3/8GRwWOs917YE4=", nonce, frameSources);
            }
        }

        private string GetHtml(string nonce)
        {
            string framesHtml = null;
            string postFormHtml = null;

            if (_result.FrontChannelLogoutRequests != null && _result.FrontChannelLogoutRequests.Any())
            {
                // now support only redirect binding
                var frameUrls = _result.FrontChannelLogoutRequests
                    .Where(x => x.Binding == Saml2Constants.ProtocolBindings.HttpRedirectString).ToList();
                if (frameUrls.Any()) 
                {
                    var redirectFrames = frameUrls.Select(request => $"<iframe src='{HtmlEncoder.Default.Encode(request.Payload)}'></iframe>");
                    framesHtml = redirectFrames.Aggregate(new StringBuilder(), (sb, v) => sb.Append(v), sb => sb.ToString());
                }

                var postForms = _result.FrontChannelLogoutRequests
                    .Where(x => x.Binding == Saml2Constants.ProtocolBindings.HttpPostString)
                    .Select((r, i) => new { request = r, index = i }).ToList();
                if (postForms.Any())
                {
                    var postFrames = postForms.Select(request => $"<iframe id='id{request.index}'></iframe>");
                    var postScripts = postForms.Select(request => 
                    {
                        var payload = request.request.Payload.Replace("\"", "'") + $"<script nonce='{nonce}'>window.setTimeout(function() {{document.forms[0].submit()\\;}}, 0)\\;\\<\\/script>";
                        return $"<script nonce='{nonce}'>var myFrame = $('#id{request.index}').contents().find('body');var form=\"{payload}\";myFrame.html(form);</script>"; 
                    });

                    postFormHtml = postFrames.Concat(postScripts).Aggregate(new StringBuilder(), (sb, v) => sb.Append(v), sb => sb.ToString());
                }
            }

            var html = new StringBuilder();
            html.Append("<!DOCTYPE html><html><head>");
            if (!string.IsNullOrEmpty(postFormHtml))
            {
                html.Append(@"<script src=""https://code.jquery.com/jquery-3.5.1.slim.min.js"" integrity=""sha256-4+XzXVhsDmqanXGHaHvgh1gMQKX40OUvDEBTu8JcmNs="" crossorigin=""anonymous""></script>");
            }

            html.Append("<style>iframe{{display:none;width:0;height:0;}}</style></head><body>");
            html.Append(framesHtml);
            html.Append(postFormHtml);
            html.Append("</body></html>");
            return html.ToString();
        }
    }
}