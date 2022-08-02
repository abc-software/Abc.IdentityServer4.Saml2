using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Events;
using IdentityServer4.Extensions;

namespace Abc.IdentityServer4.Saml2.Events
{
    public class SignInTokenIssuedFailureEvent : TokenIssuedFailureEvent
    {
        public SignInTokenIssuedFailureEvent(ValidatedSaml2Request request, string error, string description)
            : base()
        {
            if (request != null)
            {
                ClientId = request.Client?.ClientId;
                ClientName = request.Client?.ClientName;

                if (request.Subject != null && request.Subject.Identity.IsAuthenticated)
                {
                    SubjectId = request.Subject.GetSubjectId();
                }
            }

            Endpoint = Constants.EndpointNames.SingleSignOn;
            Error = error;
            ErrorDescription = description;
        }
    }
}