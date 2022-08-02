// ----------------------------------------------------------------------------
// <copyright file="Saml2SingleSignOnEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityModel;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Collections.Specialized;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2SingleSignOnEndpoint : IEndpointHandler
    {
        private readonly IUserSession _userSession;
        private readonly ILogger _logger;
        private readonly ISignInResponseGenerator _signinGenerator;
        private readonly ILogoutResponseGenerator _signoutGenerator;
        private readonly IEventService _events;
        private readonly HttpSaml2MessageSerializer _serialzer;
        private readonly ISignInInteractionResponseGenerator _interaction;
        private readonly ISaml2RequestValidator _signinValidator;
        private readonly Saml2SPOptions _options;
        private readonly IConsentMessageStore _consentResponseStore;
        private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;

        public Saml2SingleSignOnEndpoint(
            IUserSession userSession,
            ILogger<Saml2SingleSignOnEndpoint> logger,
            ISignInResponseGenerator generator,
            ISignInInteractionResponseGenerator interaction,
            ISaml2RequestValidator signinValidator,
            IConsentMessageStore consentResponseStore,
            IAuthorizationParametersMessageStore authorizationParametersMessageStore,
            Saml2SPOptions options,
            ILogoutResponseGenerator signoutGenerator,
            IEventService events,
            HttpSaml2MessageSerializer serialzer)
        {
            _userSession = userSession;
            _logger = logger;
            _signinGenerator = generator;
            _interaction = interaction;
            _signinValidator = signinValidator;
            _consentResponseStore = consentResponseStore;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
            _options = options;
            _signoutGenerator = signoutGenerator;
            _events = events;
            _serialzer = serialzer;
        }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            // user can be null here (this differs from HttpContext.User where the anonymous user is filled in)
            var user = await _userSession.GetUserAsync();

            var messageStoreId = context.Request.Query[Constants.DefaultRoutePathParams.MessageStoreIdParameterName];
            if (!string.IsNullOrWhiteSpace(messageStoreId))
            {
                return await ProcessSignInCallbackAsync(messageStoreId, user);
            }

            var requestId = context.Request.Query[Constants.DefaultRoutePathParams.RequestIdParameterName];
            if (!string.IsNullOrWhiteSpace(requestId))
            {
                return await ProcessSignOutCallbackAsync(requestId, user);
            }

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
                return await ProcessSignOutAsync(requestMessage2, user);
            }

            if (incomingMessage is HttpSaml2ResponseMessage2 responseMessage && responseMessage.Saml2Response is Saml2LogoutResponse)
            {
                return new StatusCodeResult(HttpStatusCode.OK);
            }

            return new StatusCodeResult(HttpStatusCode.BadRequest);
        }

        internal async Task<IEndpointResult> ProcessSignOutAsync(HttpSaml2RequestMessage2 signin, ClaimsPrincipal user)
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

        internal async Task<IEndpointResult> ProcessSignOutCallbackAsync(string requestId, ClaimsPrincipal user)
        {
            var data = await _authorizationParametersMessageStore.ReadAsync(requestId);
            await _authorizationParametersMessageStore.DeleteAsync(requestId);

            var requestMessage = data.Data.ToSaml2Message() as HttpSaml2RequestMessage2;
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

        internal async Task<IEndpointResult> ProcessSignInCallbackAsync(string messageStoreId, ClaimsPrincipal user)
        {
            var data = await _authorizationParametersMessageStore.ReadAsync(messageStoreId);
            await _authorizationParametersMessageStore.DeleteAsync(messageStoreId);

            var requestMessage = data.Data.ToSaml2Message() as HttpSaml2RequestMessage2;
            if (!(requestMessage?.Saml2Request is Saml2AuthenticationRequest authenticationRequest))
            {
                return await CreateSignInErrorResult("SAML2 message is not authentication request.");
            }

            var parameters = new NameValueCollection();
            parameters.Add(OidcConstants.AuthorizeRequest.ClientId, authenticationRequest.Issuer.Value);
            parameters.Add(OidcConstants.AuthorizeRequest.Nonce, authenticationRequest.Id.Value);
            //
            //parameters.Add(OidcConstants.AuthorizeRequest.Scope, message.GetParameter("scope")); // TODO: may be use 

            var consentRequest = new ConsentRequest(parameters, user?.GetSubjectId());
            var consent = await _consentResponseStore.ReadAsync(consentRequest.Id);
            if (consent != null && consent.Data == null)
            {
                return await CreateSignInErrorResult("consent message is missing data");
            }

            try
            {
                var result = await ProcessAuthenticationRequestAsync(requestMessage, user, consent?.Data);

                _logger.LogTrace("End SAML2 callback request. Result type: {0}", result?.GetType().ToString() ?? "-none-");

                return result;
            }
            finally
            {
                if (consent != null)
                {
                    await _consentResponseStore.DeleteAsync(consentRequest.Id);
                }
            }
        }

        internal async Task<IEndpointResult> ProcessAuthenticationRequestAsync(HttpSaml2RequestMessage2 signin, ClaimsPrincipal user, ConsentResponse consent = null)
        {
            if (user != null && user.Identity.IsAuthenticated)
            {
                _logger.LogDebug("User in SAML2 authentication request: {subjectId}", user.GetSubjectId());
            }
            else
            {
                _logger.LogDebug("No user present in SAML2 authentication request");
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

            await _userSession.AddClientIdAsync(validationResult.ValidatedRequest.SessionParticipant);

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
                _logger.LogError(logMessage);
            }

            if (request != null)
            {
                //logger.LogInformation("{@validationDetails}", new Logging.ValidatedSaml2RequestLog(request, new string[0]));
            }

            await _events.RaiseAsync(new Events.SignInTokenIssuedFailureEvent(request, error, errorDescription));

            return new Results.ErrorPageResult(error, errorDescription);
        }
    }
}