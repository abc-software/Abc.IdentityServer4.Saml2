using Abc.IdentityModel.Protocols.Saml2;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Stores
{
    internal class MockArtifactStore : IArtifactStore
    {
        public Dictionary<string, Saml2Response> Artifacts { get; set; } = new Dictionary<string, Saml2Response>();

        public Task<Saml2ArtifactResponseContent> GetAsync(string key)
        {
            Saml2Response val = null;
            if (key != null)
            {
                Artifacts.TryGetValue(key, out val);
            }

            return Task.FromResult<Saml2ArtifactResponseContent>(val != null ? new Saml2ArtifactResponseContent(val) : null);
        }

        public Task RemoveAsync(string key)
        {
            Artifacts.Remove(key);
            return Task.CompletedTask;
        }

        public Task StoreAsync(string key, string clientId, Saml2Response message, DateTime created, DateTime? expiration)
        {
            Artifacts[key] = message;
            return Task.CompletedTask;
        }
    }
}
