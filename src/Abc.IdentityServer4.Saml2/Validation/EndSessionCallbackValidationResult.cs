using Abc.IdentityServer4.Saml2.Services;
using IdentityServer4.Validation;
using System;
using System.Collections.Generic;
using System.Text;

namespace Abc.IdentityServer4.Saml2.Validation
{
    /// <summary>
    /// Validation result for end session callback requests.
    /// </summary>
    /// <seealso cref="ValidationResult" />
    public class EndSessionCallbackValidationResult : ValidationResult
    {
        /// <summary>
        /// Gets the client front-channel logout requests.
        /// </summary>
        public IEnumerable<Saml2LogoutRequest> FrontChannelLogoutRequests { get; set; }
    }
}