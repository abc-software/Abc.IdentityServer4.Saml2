using Abc.IdentityModel.Protocols;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    internal class Artifact4HandleGenerationService : IArtifactHandleGenerationService
    {
        private readonly IHttpContextAccessor contextAccessor;

        public Artifact4HandleGenerationService(IHttpContextAccessor contextAccessor)
        {
            this.contextAccessor = contextAccessor;
        }

        public Task<string> GenerateAsync(int length = 32)
        {
            ISamlArtifact artifact = new SamlArtifact4(1, this.contextAccessor.HttpContext.GetIdentityServerIssuerUri());
            return Task.FromResult(artifact.ToString());
        }
    }
}