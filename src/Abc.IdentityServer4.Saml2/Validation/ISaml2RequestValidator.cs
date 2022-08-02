using Abc.IdentityModel.Protocols.Saml2;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public interface ISaml2RequestValidator
    {
        Task<Saml2RequestValidationResult> ValidateAsync(HttpSaml2RequestMessage2 message, ClaimsPrincipal user);
    }
}