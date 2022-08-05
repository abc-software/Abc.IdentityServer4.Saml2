using Abc.IdentityServer4.Saml2.Validation;
using System.Collections.Specialized;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    internal class StubSaml2EndSessionRequestValidator : ISaml2EndSessionRequestValidator
    {
        public Saml2EndSessionCallbackValidationResult EndSessionCallbackValidationResult { get; set; } = new Saml2EndSessionCallbackValidationResult();

        public Task<Saml2EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters)
        {
            return Task.FromResult(EndSessionCallbackValidationResult);
        }
    }
}
