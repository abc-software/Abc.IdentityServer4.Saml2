// ----------------------------------------------------------------------------
// <copyright file="ValidatedSaml2Request.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

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