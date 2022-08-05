using Abc.IdentityServer4.Saml2.ResponseProcessing;
using FluentAssertions;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2MetadataEndpointFixture
    {
        private Saml2MetadataEndpoint _target;
        private IMetadataResponseGenerator _stubMetadataGenerator = new StubMetadataResponseGenerator();
        private DefaultHttpContext _context;

        public Saml2MetadataEndpointFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");

            _target = new Saml2MetadataEndpoint(
                _stubMetadataGenerator,
                TestLogger.Create<Saml2MetadataEndpoint>()
                );
        }

        [Fact]
        public async Task metadata_not_get_should_return_405()
        {
            _context.Request.Method = "POST";

            var result = await _target.ProcessAsync(_context);

            var statusCode = result as StatusCodeResult;
            statusCode.Should().NotBeNull();
            statusCode.StatusCode.Should().Be(405);
        }

        [Fact]
        public async Task metadata_should_return_metadata_result()
        {
            _context.Request.Method = "GET";

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<Results.MetadataResult>();
        }
    }
}
