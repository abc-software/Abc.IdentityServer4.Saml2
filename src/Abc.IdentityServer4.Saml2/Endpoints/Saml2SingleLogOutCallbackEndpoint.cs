// ----------------------------------------------------------------------------
// <copyright file="Saml2SingleLogOutCallbackEndpoint.cs" company="ABC software Ltd">
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
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2SingleLogOutCallbackEndpoint : Saml2SingleSignOnEndpointBase
    {
        private readonly ISaml2RequestValidator _signinValidator;
        private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;
        private readonly ILogoutResponseGenerator _signoutGenerator;

        public Saml2SingleLogOutCallbackEndpoint(
            IUserSession userSession,
            ILogger<Saml2SingleLogOutCallbackEndpoint> logger,
            ISignInResponseGenerator generator,
            ISignInInteractionResponseGenerator interaction,
            ISaml2RequestValidator signinValidator,
            IAuthorizationParametersMessageStore authorizationParametersMessageStore,
            Saml2SPOptions options,
            ILogoutResponseGenerator signoutGenerator,
            IEventService events) 
            : base(userSession, logger, generator, interaction, signinValidator, options, events)
        {
            _signinValidator = signinValidator;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
            _signoutGenerator = signoutGenerator;
        }

        public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            Logger.LogDebug("Start SAML2 logout callback request");

            if (!HttpMethods.IsGet(context.Request.Method))
            {
                Logger.LogWarning("Invalid HTTP method for SAML2 logout callback endpoint.");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            var requestId = (string)context.Request.Query[Constants.DefaultRoutePathParams.RequestIdParameterName];
            var data = await _authorizationParametersMessageStore.ReadAsync(requestId);
            if (requestId != null)
            {
                await _authorizationParametersMessageStore.DeleteAsync(requestId);
            }

            if (data?.Data == null || !data.Data.Any())
            {
                return await CreateSignInErrorResult("SAML2 message is missing data.");
            }

            var requestMessage = data.Data.ToSaml2Message() as HttpSaml2RequestMessage2;
            if (!(requestMessage?.Saml2Request is Saml2LogoutRequest))
            {
                return await CreateSignInErrorResult("SAML2 message is not logout request.");
            }

            // user can be null here (this differs from HttpContext.User where the anonymous user is filled in)
            var user = await UserSession.GetUserAsync();

            var validationResult = await _signinValidator.ValidateAsync(requestMessage, user);
            if (validationResult.IsError)
            {
                return await CreateSignInErrorResult(
                    "SAML2 sign out request validation failed",
                    validationResult.ValidatedRequest,
                    validationResult.Error,
                    validationResult.ErrorDescription);
            }

            var responseMessage = await _signoutGenerator.GenerateResponseAsync(validationResult);

            return new Results.SignInResult(responseMessage);
        }
    }
}