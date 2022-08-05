using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Sustainsys.Saml2.Metadata;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    internal class StubMetadataResponseGenerator : IMetadataResponseGenerator
    {
        public MetadataBase Metadata { get; set; } = new EntityDescriptor(new EntityId("urn:issuer"));

        public Task<MetadataBase> GenerateMetadata()
        {
            return Task.FromResult(Metadata);
        }
    }
}