// ----------------------------------------------------------------------------
// <copyright file="Saml2SingleSignOnEndpointBase.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal abstract class Saml2SingleSignOnEndpointBase : IEndpointHandler
    {
        private readonly ISignInResponseGenerator _signinGenerator;
        private readonly IEventService _events;
        private readonly ISignInInteractionResponseGenerator _interaction;
        private readonly ISaml2RequestValidator _signinValidator;
        private readonly Saml2SPOptions _options;

        protected Saml2SingleSignOnEndpointBase(
            IUserSession userSession,
            ILogger logger,
            ISignInResponseGenerator generator,
            ISignInInteractionResponseGenerator interaction,
            ISaml2RequestValidator signinValidator,
            Saml2SPOptions options,
            IEventService events)
        {
            UserSession = userSession;
            Logger = logger;
            _signinGenerator = generator;
            _interaction = interaction;
            _signinValidator = signinValidator;
            _options = options;
            _events = events;
        }

        protected ILogger Logger { get; }

        protected IUserSession UserSession { get; }

        public abstract Task<IEndpointResult> ProcessAsync(HttpContext context);

        protected internal async Task<IEndpointResult> ProcessLogoutOutRequestAsync(HttpSaml2RequestMessage2 signin, ClaimsPrincipal user)
        {
            var validationResult = await _signinValidator.ValidateAsync(signin, user);
            if (validationResult.IsError)
            {
                return await CreateSignInErrorResult(
                    "SAML2 sign out request validation failed",
                    validationResult.ValidatedRequest,
                    validationResult.Error,
                    validationResult.ErrorDescription);
            }

            return new Results.SignOutResult(validationResult.ValidatedRequest);
        }

        protected internal async Task<IEndpointResult> ProcessAuthenticationRequestAsync(HttpSaml2RequestMessage2 signin, ClaimsPrincipal user, ConsentResponse consent = null)
        {
            if (user != null && user.Identity.IsAuthenticated)
            {
                Logger.LogDebug("User in SAML2 authentication request: {subjectId}", user.GetSubjectId());
            }
            else
            {
                Logger.LogDebug("No user present in SAML2 authentication request");
            }

            var validationResult = await _signinValidator.ValidateAsync(signin, user);
            if (validationResult.IsError)
            {
                return await CreateSignInErrorResult(
                    "SAML2 sign in request validation failed",
                    validationResult.ValidatedRequest,
                    validationResult.Error,
                    validationResult.ErrorDescription);
            }

            var interactionResult = await _interaction.ProcessInteractionAsync(validationResult.ValidatedRequest, consent);
            if (interactionResult.IsError)
            {
                return await CreateSignInErrorResult(
                    "SAML2 interaction generator error",
                    validationResult.ValidatedRequest,
                    interactionResult.Error,
                    interactionResult.ErrorDescription,
                    false);
            }

            if (interactionResult.IsLogin)
            {
                return new Results.LoginPageResult(validationResult.ValidatedRequest);
            }

            if (interactionResult.IsRedirect)
            {
                return new Results.CustomRedirectResult(validationResult.ValidatedRequest, interactionResult.RedirectUrl);
            }

            var responseMessage = await _signinGenerator.GenerateResponseAsync(validationResult);

            await UserSession.AddClientIdAsync(validationResult.ValidatedRequest.SessionParticipant);

            await _events.RaiseAsync(new Events.SignInTokenIssuedSuccessEvent(responseMessage, validationResult));

            return new Results.SignInResult(responseMessage);
        }

        protected async Task<IEndpointResult> CreateSignInErrorResult(
            string logMessage,
            Validation.ValidatedSaml2Request request = null,
            string error = "server_error",
            string errorDescription = null,
            bool logError = true)
        {
            if (logError)
            {
                Logger.LogError(logMessage);
            }

            if (request != null)
            {
                Logger.LogInformation("{@validationDetails}", new Logging.ValidatedSaml2RequestLog(request, new string[0]));
            }

            await _events.RaiseAsync(new Events.SignInTokenIssuedFailureEvent(request, error, errorDescription));

            return new Results.ErrorPageResult(error, errorDescription);
        }
    }
}