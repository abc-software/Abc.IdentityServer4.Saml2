using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Stores;
using FluentAssertions;
using IdentityServer4.Stores;
using System;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Stores.UnitTests
{
    public class DefaultArtifactStoreFixture
    {
        private InMemoryPersistedGrantStore _store = new InMemoryPersistedGrantStore();
        private IArtifactStore _artifacts;

        public DefaultArtifactStoreFixture()
        {
            _artifacts = new DefaultArtifactStore(_store,
                    TestLogger.Create<DefaultArtifactStore>());
        }

        [Fact]
        public async Task StoreArtifactStoreAsync_should_persist_grant()
        {
            var key = "key";
            var message = new Saml2Response(new Saml2Status(Saml2StatusCode.Success));

            await _artifacts.StoreAsync(key, "test", message, DateTime.UtcNow, null);
            var artifact = await _artifacts.GetAsync(key);

            artifact.ResponseXml.OuterXml.Should().Contain("Response");
        }

        [Fact]
        public async Task RemoveAuthorizationCodeAsync_should_remove_grant()
        {
            var key = "key";
            var message = new Saml2Response(new Saml2Status(Saml2StatusCode.Success));

            await _artifacts.StoreAsync(key, "test", message, DateTime.UtcNow, null);
            await _artifacts.RemoveAsync(key);
            var artifact = await _artifacts.GetAsync(key);
            artifact.Should().BeNull();
        }

    }
}
