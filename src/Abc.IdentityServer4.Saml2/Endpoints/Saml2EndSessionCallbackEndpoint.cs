// ----------------------------------------------------------------------------
// <copyright file="Saml2EndSessionCallbackEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2EndSessionCallbackEndpoint : IEndpointHandler
    {
        private readonly ISaml2EndSessionRequestValidator _endSessionRequestValidator;
        private readonly ILogger _logger;

        public Saml2EndSessionCallbackEndpoint(
            ISaml2EndSessionRequestValidator endSessionRequestValidator,
            ILogger<Saml2EndSessionCallbackEndpoint> logger)
        {
            _endSessionRequestValidator = endSessionRequestValidator;
            _logger = logger;
        }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            if (!HttpMethods.IsGet(context.Request.Method))
            {
                _logger.LogWarning("Invalid HTTP method for end session callback endpoint.");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            _logger.LogDebug("Processing end session callback request");

            var parameters = context.Request.Query.AsNameValueCollection();
            var result = await _endSessionRequestValidator.ValidateCallbackAsync(parameters);

            if (!result.IsError)
            {
                _logger.LogInformation("Successful end session callback.");
            }
            else
            {
                _logger.LogError("Error validating end session callback: {error}", result.Error);
            }

            return new Results.EndSessionCallbackResult(result);
        }
    }
}