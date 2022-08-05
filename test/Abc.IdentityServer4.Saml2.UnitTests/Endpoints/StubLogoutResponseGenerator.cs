using System;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.UnitTests
{
    internal class StubLogoutResponseGenerator : ILogoutResponseGenerator
    {
        public HttpSaml2Message2 Message { get; set; } = new HttpSaml2ResponseMessage2("http://client".ToUri(), "some_response");

        public Task<HttpSaml2Message2> GenerateResponseAsync(Saml2RequestValidationResult validationResult)
        {
            return Task.FromResult(Message);
        }
    }
}