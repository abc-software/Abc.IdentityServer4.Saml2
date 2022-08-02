using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using System.Collections.Generic;

namespace Abc.IdentityServer4.Saml2.Events
{
    public class SignInTokenIssuedSuccessEvent : TokenIssuedSuccessEvent
    {
        public SignInTokenIssuedSuccessEvent(HttpSaml2Message2 responseMessage, Saml2RequestValidationResult request)
            : base()
        {
            ClientId = request.ValidatedRequest.Client?.ClientId;
            ClientName = request.ValidatedRequest.Client?.ClientName;
            Endpoint = Constants.EndpointNames.SingleSignOn;
            SubjectId = request.ValidatedRequest.Subject?.GetSubjectId();
            Scopes = request.ValidatedRequest.ValidatedResources?.RawScopeValues.ToSpaceSeparatedString();

            var tokens = new List<Token>();
            tokens.Add(new Token("SecurityToken", (responseMessage as IHttpSaml2EncodedMessage)?.Data));
            Tokens = tokens;
        }
    }
}