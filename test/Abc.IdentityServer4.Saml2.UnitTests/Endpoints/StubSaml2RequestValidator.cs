using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    internal class StubSaml2RequestValidator : ISaml2RequestValidator
    {
        internal Saml2RequestValidationResult Result { get; set; }

        public Task<Saml2RequestValidationResult> ValidateAsync(HttpSaml2RequestMessage2 message, ClaimsPrincipal user)
        {
            return Task.FromResult(Result);
        }
    }
}