using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4.Validation;
using System.Collections.Generic;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public class ValidatedSaml2Request : ValidatedRequest
    {
        public HttpSaml2RequestMessage2 Saml2RequestMessage { get; set; }

        public Stores.RelyingParty RelyingParty { get; set; }

        public string ReplyUrl { get; set; }

        public IEnumerable<string> ClientIds { get; set; }
        
        public Saml2SessionParticipant SessionParticipant { get; set; }
    }
}