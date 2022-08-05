// ----------------------------------------------------------------------------
// <copyright file="ValidatedSaml2RequestLog.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2.Validation;
using IdentityModel;
using System.Collections.Generic;

namespace Abc.IdentityServer4.Saml2.Logging
{
    internal class ValidatedSaml2RequestLog
    {
        public ValidatedSaml2RequestLog(ValidatedSaml2Request request, IEnumerable<string> sensitiveValuesFilter)
        {
            // TODO: Raw = request.Saml2RequestMessage.ToScrubbedDictionary(sensitiveValuesFilter.ToArray());
            ClientId = request.ClientId;
            ReplyUrl = request.ReplyUrl;

            if (request.Client != null)
            {
                ClientName = request.Client.ClientName;
                AllowedRedirectUris = request.Client.RedirectUris;
                AllowedPostLogoutRedirectUris = request.Client.PostLogoutRedirectUris;
            }

            if (request.Subject != null)
            {
                var subjectClaim = request.Subject.FindFirst(JwtClaimTypes.Subject);
                SubjectId = subjectClaim != null ? subjectClaim.Value : "anonymous";
            }
        }

        public string ClientId { get; set; }
        public string ClientName { get; set; }
        public string ReplyUrl { get; set; }
        public IEnumerable<string> AllowedRedirectUris { get; set; }
        public IEnumerable<string> AllowedPostLogoutRedirectUris { get; set; }
        public string SubjectId { get; set; }
        public Dictionary<string, string> Raw { get; set; }

        public override string ToString()
        {
            return LogSerializer.Serialize(this);
        }
    }
}