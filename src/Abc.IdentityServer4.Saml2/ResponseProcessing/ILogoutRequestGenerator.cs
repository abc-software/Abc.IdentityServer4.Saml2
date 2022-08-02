using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    internal interface ILogoutRequestGenerator
    {
        Task<HttpSaml2Message2> GenerateRequestAsync(Saml2RequestValidationResult validationResult);
    }
}