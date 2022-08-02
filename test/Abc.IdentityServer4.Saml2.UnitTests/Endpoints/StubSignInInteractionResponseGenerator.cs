using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoint.UnitTests
{
    internal class StubSignInInteractionResponseGenerator : ISignInInteractionResponseGenerator
    {
        internal InteractionResponse Response { get; set; } = new InteractionResponse();

        public Task<InteractionResponse> ProcessInteractionAsync(ValidatedSaml2Request request, ConsentResponse consent = null)
        {
            return Task.FromResult(Response);
        }
    }
}