using Abc.IdentityServer4.Saml2.IntegrationTests.Common;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Xml.Linq;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.IntegrationTests
{
    public class Saml2MetadataEndpointFixture
    {
        private const string Category = "SAML2 metadata endpoint";

        [Fact]
        [Trait("Category", Category)]
        public async Task entityId_should_be_lowercase()
        {
            IdentityServerPipeline pipeline = new IdentityServerPipeline();
            pipeline.Initialize("/ROOT");

            var result = await pipeline.BackChannelClient.GetAsync("HTTPS://SERVER/ROOT/SAML2/METADATA");

            var xml = await result.Content.ReadAsStringAsync();
            var data = XDocument.Parse(xml);
            var issuer = data.Root.Attribute("entityID").Value;

            issuer.Should().Be("https://server/root");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task when_lower_case_issuer_option_disabled_issuer_uri_should_be_preserved()
        {
            IdentityServerPipeline pipeline = new IdentityServerPipeline();
            pipeline.Initialize("/ROOT");

            pipeline.Options.LowerCaseIssuerUri = false;

            var result = await pipeline.BackChannelClient.GetAsync("HTTPS://SERVER/ROOT/SAML2/METADATA");

            var xml = await result.Content.ReadAsStringAsync();
            var data = XDocument.Parse(xml);
            var issuer = data.Root.Attribute("entityID").Value;

            issuer.Should().Be("https://server/ROOT");
        }

        [Fact]
        [Trait("Category", Category)]
        public async Task Algorithms_supported_should_match_signing_key()
        {
            const string ns = "urn:oasis:names:tc:SAML:2.0:metadata";

            IdentityServerPipeline pipeline = new IdentityServerPipeline();
            pipeline.Initialize();

            var result = await pipeline.BackChannelClient.GetAsync(IdentityServerPipeline.Saml2MetadataEndpoint);
            
            var xml = await result.Content.ReadAsStringAsync();
            var data = XDocument.Parse(xml);

            var descriptor = data.Root.Element(XName.Get("IDPSSODescriptor", ns));

            var ars = descriptor.Element(XName.Get("ArtifactResolutionService", ns));
            ars.Attribute("Binding").Value.Should().Be("urn:oasis:names:tc:SAML:2.0:bindings:SOAP");
            ars.Attribute("Location").Value.Should().Be("https://server/saml2/ars");
            ars.Attribute("index").Value.Should().Be("0");
        }
    }
}

