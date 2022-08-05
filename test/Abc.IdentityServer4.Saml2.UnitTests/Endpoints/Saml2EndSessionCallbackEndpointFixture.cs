using Abc.IdentityServer4.Saml2.Endpoints.Results;
using FluentAssertions;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2EndSessionCallbackEndpointFixture
    {
        private Saml2EndSessionCallbackEndpoint _subject;
        private DefaultHttpContext _context;
        private StubSaml2EndSessionRequestValidator _stubEndSessionRequestValidator = new StubSaml2EndSessionRequestValidator();

        public Saml2EndSessionCallbackEndpointFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Request.Method = "GET";

            _subject = new Saml2EndSessionCallbackEndpoint(
                _stubEndSessionRequestValidator,
                TestLogger.Create<Saml2EndSessionCallbackEndpoint>()
                );
        }

        [Fact]
        public async Task post_to_entry_point_should_return_405()
        {
            _context.Request.Method = "POST";

            var result = await _subject.ProcessAsync(_context);

            result.Should().BeOfType<StatusCodeResult>();
            var statusCode = result as StatusCodeResult;
            statusCode.StatusCode.Should().Be(405);
        }

        [Fact]
        public async Task get_with_validatation_error_should_return_endsessioncallback_result()
        {
            _stubEndSessionRequestValidator.EndSessionCallbackValidationResult.IsError = true;

            var result = await _subject.ProcessAsync(_context);

            result.Should().BeOfType<EndSessionCallbackResult>();
        }

        [Fact]
        public async Task get_without_validatation_error_should_return_endsessioncallback_result()
        {
            _stubEndSessionRequestValidator.EndSessionCallbackValidationResult.IsError = false;

            var result = await _subject.ProcessAsync(_context);

            result.Should().BeOfType<EndSessionCallbackResult>();
        }
    }
}
