using Abc.IdentityModel.Metadata;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    internal class StubMetadataResponseGenerator : IMetadataResponseGenerator
    {
        public DescriptorBase Metadata { get; set; } = new EntityDescriptor(new EntityId("urn:issuer"));

        public Task<DescriptorBase> GenerateMetadata()
        {
            return Task.FromResult(Metadata);
        }
    }
}