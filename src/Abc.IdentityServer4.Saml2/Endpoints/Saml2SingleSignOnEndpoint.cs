// ----------------------------------------------------------------------------
// <copyright file="Saml2SingleSignOnEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Hosting;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2SingleSignOnEndpoint : Saml2SingleSignOnEndpointBase
    {
        private readonly HttpSaml2MessageSerializer _serialzer;

        public Saml2SingleSignOnEndpoint(
            IUserSession userSession,
            ILogger<Saml2SingleSignOnEndpoint> logger,
            ISignInResponseGenerator generator,
            ISignInInteractionResponseGenerator interaction,
            ISaml2RequestValidator signinValidator,
            Saml2SPOptions options,
            IEventService events,
            HttpSaml2MessageSerializer serialzer) 
            : base(userSession, logger, generator, interaction, signinValidator, options, events)
        {
            _serialzer = serialzer;
        }

        public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            // user can be null here (this differs from HttpContext.User where the anonymous user is filled in)
            var user = await UserSession.GetUserAsync();

            if (!_serialzer.TryReadMessage<HttpSaml2Message2>(context.Request, out var incomingMessage))
            {
                return new StatusCodeResult(HttpStatusCode.BadRequest);
            }

            if (incomingMessage is HttpSaml2RequestMessage2 requestMessage && requestMessage.Saml2Request is Saml2AuthenticationRequest)
            {
                return await ProcessAuthenticationRequestAsync(requestMessage, user);
            }

            if (incomingMessage is HttpSaml2RequestMessage2 requestMessage2 && requestMessage2.Saml2Request is Saml2LogoutRequest)
            {
                return await ProcessLogoutOutRequestAsync(requestMessage2, user);
            }

            if (incomingMessage is HttpSaml2ResponseMessage2 responseMessage && responseMessage.Saml2Response is Saml2LogoutResponse)
            {
                return new StatusCodeResult(HttpStatusCode.OK);
            }

            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }
    }
}