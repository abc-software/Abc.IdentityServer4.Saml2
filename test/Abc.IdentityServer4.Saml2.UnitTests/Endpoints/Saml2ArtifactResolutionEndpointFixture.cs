using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Stores;
using FluentAssertions;
using IdentityServer4.Configuration;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    public class Saml2ArtifactResolutionEndpointFixture
    {
        private MockKeyMaterialService _mockKeyMaterialService = new MockKeyMaterialService();
        private IdentityServerOptions _options = new IdentityServerOptions() {  IssuerUri = "https://idp.example.org/SAML2" };
        private IHttpContextAccessor _mockContextAccessor;
        private MockArtifactStore _mockArtifactStore = new MockArtifactStore();
        private Saml2ArtifactResolutionEndpoint _target;
        private HttpContext _context;

        public Saml2ArtifactResolutionEndpointFixture()
        {
            _mockContextAccessor = new MockHttpContextAccessor(options: _options);

            string xmlBody = @"
<soap:Envelope xmlns:soap=""http://schemas.xmlsoap.org/soap/envelope/"">
<soap:Body>
<samlp:ArtifactResolve xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
    ID=""_cce4ee769ed970b501d680f697989d14""
    Version=""2.0""
    IssueInstant=""2004-12-05T09:21:58Z"">
    <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
    <samlp:Artifact>AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8=</samlp:Artifact>
</samlp:ArtifactResolve>
</soap:Body>
</soap:Envelope>
";

            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();
            _context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(xmlBody));
            _context.Request.Method = "POST";
            _context.Request.ContentType = @"text/xml; charset=""utf-8""";
            _context.Request.Headers["SOAPAction"] = "http://www.oasis-open.org/committees/security";

            _target = new Saml2ArtifactResolutionEndpoint(
                _mockArtifactStore,
                _mockContextAccessor,
                _mockKeyMaterialService,
                TestLogger.Create<Saml2ArtifactResolutionEndpoint>()
                );
        }

        [Fact]
        public async Task invalid_method_should_return_405()
        {
            _context.Request.Method = "GET";

            var result = await _target.ProcessAsync(_context);
            result.Should().BeOfType<StatusCodeResult>();
            var statusCode = result as StatusCodeResult;
            statusCode.StatusCode.Should().Be(405);
        }


        [Fact]
        public async Task invalid_mediatype_should_return_415()
        {
            _context.Request.ContentType = "application/xml";

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<StatusCodeResult>();
            var statusCode = result as StatusCodeResult;
            statusCode.StatusCode.Should().Be(415);
        }

        [Fact]
        public async Task invalid_soapaction_should_return_400()
        {
            _context.Request.Headers["SOAPAction"] = "http://tempuri.org";

            var result = await _target.ProcessAsync(_context);

            result.Should().BeOfType<StatusCodeResult>();
            var statusCode = result as StatusCodeResult;
            statusCode.StatusCode.Should().Be(400);
        }

        //[Fact]
        //public async Task invalid_soapversion_should_return_500()
        //{
        //    var result = await _target.ProcessAsync(_context);

        //    result.Should().BeOfType<StatusCodeResult>();
        //    var statusCode = result as StatusCodeResult;
        //    statusCode.StatusCode.Should().Be(500);
        //}

        [Fact]
        public async Task valid_request_should_return_response()
        {
            _mockKeyMaterialService.SigningCredentials.Add(TestCert.LoadSigningCredentials());
            _mockArtifactStore.Artifacts["AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8="] =
                new Saml2Response(new Saml2Status(Saml2StatusCode.Success));

            var result = await _target.ProcessAsync(_context);

            //result.Should().BeOfType<BodyWriter>

            _mockArtifactStore.Artifacts.Should().BeEmpty();
        }

    }
}
