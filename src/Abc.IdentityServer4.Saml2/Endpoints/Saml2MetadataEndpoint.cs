// ----------------------------------------------------------------------------
// <copyright file="Saml2MetadataEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2.ResponseProcessing;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2MetadataEndpoint : IEndpointHandler
    {
        private readonly IMetadataResponseGenerator _generator;
        private readonly ILogger _logger;

        public Saml2MetadataEndpoint(IMetadataResponseGenerator generator, ILogger<Saml2MetadataEndpoint> logger)
        {
            _generator = generator;
            _logger = logger;
        }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            if (!HttpMethods.IsGet(context.Request.Method))
            {
                _logger.LogWarning("Metadata endpoint only supports GET requests");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            _logger.LogDebug("Start SAML2 metadata request");

            return new Results.MetadataResult(await _generator.GenerateMetadata());
        }
    }
}