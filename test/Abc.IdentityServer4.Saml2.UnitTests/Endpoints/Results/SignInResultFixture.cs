using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using FluentAssertions;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results.UnitTests
{
    public class SignInResultFixture
    {
        private SignInResult _target;
        private IdentityServerOptions _options;
        private HttpSaml2MessageSerializer _serializer;
        private DefaultHttpContext _context;
        private HttpSaml2Message2 _message;

        public SignInResultFixture()
        {
            _options = new IdentityServerOptions();

            _serializer = new HttpSaml2MessageSerializer(null);

            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();

            _message = new HttpSaml2ResponseMessage2(new Uri("http://client/callback"), "some_result", HttpDeliveryMethods.PostRequest);

            _target = new SignInResult(_message, _serializer, _options);
        }

        [Fact]
        public void signin_ctor()
        {
            Action action = () =>
            {
                _target = new SignInResult(null, _serializer, _options);
            };

            action.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public async Task form_post_mode_should_pass_results_in_body()
        {
            _target.Message.Should().NotBeNull();
            _target.Message.BaseUri.Should().Be(new Uri("http://client/callback"));

            await _target.ExecuteAsync(_context);

            _context.Response.StatusCode.Should().Be(200);
            _context.Response.ContentType.Should().StartWith("text/html");

            _context.Response.Headers.Should().ContainKey("Cache-Control");
            var cacheControl = _context.Response.Headers["Cache-Control"].First();
            cacheControl.Should().Contain("no-store");
            cacheControl.Should().Contain("max-age=0");

            _context.Response.Headers.Should().ContainKey("Content-Security-Policy");
            var csp = _context.Response.Headers["Content-Security-Policy"].First();
            csp.Should().Contain("default-src 'none';");
            csp.Should().Contain("script-src 'sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec='");

            _context.Response.Headers.Should().ContainKey("X-Content-Security-Policy");
            var xcsp = _context.Response.Headers["X-Content-Security-Policy"].First();
            xcsp.Should().Contain("default-src 'none';");
            xcsp.Should().Contain("script-src 'sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec='");

            _context.Response.Body.Seek(0, SeekOrigin.Begin);
            using (var rdr = new StreamReader(_context.Response.Body))
            {
                var html = rdr.ReadToEnd();
                html.Should().Contain(@"form class=""load"" method=""POST"" name=""hiddenform"" action=""http://client/callback"">");
                html.Should().Contain(@"<input type=""hidden"" name=""SAMLResponse"" value=""some_result"" />");
            }
        }

        [Fact]
        public async Task form_post_mode_should_add_unsafe_inline_for_csp_level_1()
        {
            _options.Csp.Level = CspLevel.One;

            await _target.ExecuteAsync(_context);

            _context.Response.Headers.Should().ContainKey("Content-Security-Policy");
            var csp = _context.Response.Headers["Content-Security-Policy"].First();
            csp.Should().Contain("script-src 'unsafe-inline' 'sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec='");

            _context.Response.Headers.Should().ContainKey("X-Content-Security-Policy");
            var xcsp = _context.Response.Headers["X-Content-Security-Policy"].First();
            xcsp.Should().Contain("script-src 'unsafe-inline' 'sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec='");
        }

        [Fact]
        public async Task form_post_mode_should_not_add_deprecated_header_when_it_is_disabled()
        {
            _options.Csp.AddDeprecatedHeader = false;

            await _target.ExecuteAsync(_context);

            _context.Response.Headers.Should().ContainKey("Content-Security-Policy");
            _context.Response.Headers.Should().NotContainKey("X-Content-Security-Policy");
        }

        [Fact]
        public async Task redirect_mode_should_not_add_csp_headers()
        {
            _target.Message = new HttpSaml2ArtifactMessage2(new Uri("http://client/callback"), "some_artifact");

            await _target.ExecuteAsync(_context);

            _context.Response.Headers.Should().NotContainKey("Cache-Control");
            _context.Response.Headers.Should().NotContainKey("Content-Security-Policy");
            _context.Response.Headers.Should().NotContainKey("X-Content-Security-Policy");
        }
    }
}