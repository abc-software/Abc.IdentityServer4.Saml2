// ----------------------------------------------------------------------------
// <copyright file="DefaultClaimsService.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Validation;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    /// <summary>
    /// Default claims service implementation.
    /// </summary>
    public class DefaultClaimsService : IClaimsService
    {
#pragma warning disable SA1401 // Fields should be private
        /// <summary>
        /// The logger.
        /// </summary>
        protected readonly ILogger Logger;

        /// <summary>
        /// The profile service.
        /// </summary>
        protected readonly IProfileService Profile;
#pragma warning restore SA1401 // Fields should be private

        private const string ShortClaimTypeProperty = "http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName";

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultClaimsService"/> class.
        /// </summary>
        /// <param name="profile">The profile service.</param>
        /// <param name="logger">The logger.</param>
        public DefaultClaimsService(IProfileService profile, ILogger<DefaultClaimsService> logger)
        {
            this.Profile = profile;
            this.Logger = logger;
        }

        /// <inheritdoc/>
        public virtual async Task<IEnumerable<Claim>> GetClaimsAsync(ValidatedRequest validatedRequest, IEnumerable<string> requestedClaimTypes)
        {
            this.Logger.LogDebug(
                "Getting claims for SAML2 token for subject: {subject} and client: {clientId}",
                validatedRequest.Subject.GetSubjectId(),
                validatedRequest.Client.ClientId);

            var ctx = new ProfileDataRequestContext(validatedRequest.Subject, validatedRequest.Client, "SAML2P", requestedClaimTypes)
            {
                RequestedResources = validatedRequest.ValidatedResources,
                ValidatedRequest = validatedRequest,
            };

            await this.Profile.GetProfileDataAsync(ctx);
            return ctx.IssuedClaims;
        }

        /// <inheritdoc/>
        public virtual IEnumerable<Claim> MapClaims(IDictionary<string, string> claimsMapping, IEnumerable<Claim> claims)
        {
            var outboundClaims = new List<Claim>();
            foreach (var claim in claims)
            {
                var claimType = claim.Type;
                if (claimsMapping.ContainsKey(claimType))
                {
                    var outboundClaim = new Claim(claimsMapping[claimType], claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer);
                    outboundClaim.Properties.Add(ShortClaimTypeProperty, claimType);
                    foreach (var claimProperty in claim.Properties)
                    {
                        outboundClaim.Properties.Add(claimProperty);
                    }

                    outboundClaims.Add(outboundClaim);

                    continue;
                }

                outboundClaims.Add(claim);
            }

            return outboundClaims;
        }
    }
}