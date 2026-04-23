using Abc.IdentityModel.Metadata;
using Abc.IdentityServer.Saml2.ResponseProcessing;
using System.Threading.Tasks;

namespace Abc.IdentityServer.Saml2.Endpoints.UnitTests
{
    internal class StubMetadataResponseGenerator : IMetadataResponseGenerator
    {
        public DescriptorBase Metadata { get; set; } = new EntityDescriptor(new EntityId("urn:issuer"));

        public Task<DescriptorBase> GenerateMetadataAsync()
        {
            return Task.FromResult(Metadata);
        }
    }
}