using Abc.IdentityServer4.Saml2.Services;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results.UnitTests
{
    public class EndSessionCallbackResultFixture
    {
        private EndSessionCallbackResult _target;
        private DefaultHttpContext _context;
        private IdentityServerOptions _options;
        private readonly Saml2EndSessionCallbackValidationResult _validationResult;

        public EndSessionCallbackResultFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();

            _options = new IdentityServerOptions();

            _validationResult = new Saml2EndSessionCallbackValidationResult() { IsError = false };

            _target = new EndSessionCallbackResult(_validationResult, _options);
        }

        [Fact]
        public async Task default_options_should_emit_frame_src_csp_headers()
        {
            _validationResult.FrontChannelLogoutRequests = new List<Saml2LogoutRequest>() {
                { new Saml2LogoutRequest("payload", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "http://foo") },
                };

            await _target.ExecuteAsync(_context);
            _context.Response.Headers.Should().ContainKey("Content-Security-Policy");
            var scp = _context.Response.Headers["Content-Security-Policy"].First();
            scp.Should().Contain("frame-src http://foo");
        }

        [Fact]
        public async Task relax_csp_options_should_prevent_frame_src_csp_headers()
        {
            _options.Authentication.RequireCspFrameSrcForSignout = false;

            _validationResult.FrontChannelLogoutRequests = new List<Saml2LogoutRequest>() {
                { new Saml2LogoutRequest("payload", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "http://foo") },
                };

            await _target.ExecuteAsync(_context);

            _context.Response.Headers.Should().NotContainKey("Content-Security-Policy");
        }
    }
}