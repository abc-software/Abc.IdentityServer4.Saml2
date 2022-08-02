// ----------------------------------------------------------------------------
// <copyright file="SignInInteractionResponseGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    /// <summary>
    /// Default logic for determining if user must login or consent when making requests to the SAML2 single sign on endpoint.
    /// </summary>
    /// <seealso cref="Abc.IdentityServer4.Saml2.ResponseProcessing.ISignInInteractionResponseGenerator" />
    public class SignInInteractionResponseGenerator : ISignInInteractionResponseGenerator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignInInteractionResponseGenerator"/> class.
        /// </summary>
        /// <param name="clock">The clock.</param>
        /// <param name="logger">The logger.</param>
        public SignInInteractionResponseGenerator(ISystemClock clock, ILogger<SignInInteractionResponseGenerator> logger)
        {
            Clock = clock;
            Logger = logger;
        }

        /// <summary>
        /// Gets the logger.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the clock.
        /// </summary>
        protected ISystemClock Clock { get; }

        /// <inheritdoc/>
        public virtual async Task<InteractionResponse> ProcessInteractionAsync(ValidatedSaml2Request request, ConsentResponse consent = null)
        {
            var interactionResponse = await ProcessLoginAsync(request);
            if (!interactionResponse.IsLogin && !interactionResponse.IsError && !interactionResponse.IsRedirect)
            {
                interactionResponse = await ProcessConsentAsync(request, consent);
            }

            var message = request.Saml2RequestMessage?.Saml2Request as Saml2AuthenticationRequest;
            if (message is null)
            {
                throw new InvalidOperationException("Request MUST be Saml2AuthenticationRequest");
            }

            if ((interactionResponse.IsLogin
                || interactionResponse.IsConsent
                || interactionResponse.IsRedirect)
                && message.IsPassive)
            {
                // IsPassive=true means do not show the UI
                Logger.LogInformation("Changing response to LoginRequired: IsPassive=true was requested");
                interactionResponse = new InteractionResponse
                {
                    Error = interactionResponse.IsLogin ? OidcConstants.AuthorizeErrors.LoginRequired :
                                interactionResponse.IsConsent ? OidcConstants.AuthorizeErrors.ConsentRequired :
                                    OidcConstants.AuthorizeErrors.InteractionRequired,
                };
            }

            return interactionResponse;
        }

        /// <summary>
        /// Processes the login logic.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <returns>The interaction response.</returns>
        protected virtual Task<InteractionResponse> ProcessLoginAsync(ValidatedSaml2Request request)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            var message = request.Saml2RequestMessage?.Saml2Request as Saml2AuthenticationRequest;
            if (message is null)
            {
                throw new InvalidOperationException("Request MUST be Saml2AuthenticationRequest");
            }

            if (message.ForceAuthentication)
            {
                // set force authentication to false so when we redirect back in from login page
                // we won't think we need to force a authentication again
                message.ForceAuthentication = false;

                Logger.LogInformation("Showing login: Requested force authentication.");
                return Task.FromResult(new InteractionResponse { IsLogin = true });
            }

            // unauthenticated user
            var user = request.Subject;
            if (!user.IsAuthenticated())
            {
                Logger.LogInformation("Showing login: User is not authenticated");
                return Task.FromResult(new InteractionResponse { IsLogin = true });
            }

            // check if idp login hint matches current provider
            string currentIdp = user.GetIdentityProvider();
            string idp = message.GetIdP();
            if (idp.IsPresent() && idp != currentIdp)
            {
                Logger.LogInformation("Showing login: Current IdP ({currentIdp}) is not the requested IdP ({idp})", currentIdp, idp);
                return Task.FromResult(new InteractionResponse { IsLogin = true });
            }

            // check local idp restrictions
            if (currentIdp == IdentityServerConstants.LocalIdentityProvider)
            {
                if (!request.Client.EnableLocalLogin)
                {
                    Logger.LogInformation("Showing login: User logged in locally, but client does not allow local logins");
                    return Task.FromResult(new InteractionResponse { IsLogin = true });
                }
            }
            // check external idp restrictions if user not using local idp
            else if (request.Client.IdentityProviderRestrictions != null &&
                request.Client.IdentityProviderRestrictions.Any() &&
                !request.Client.IdentityProviderRestrictions.Contains(currentIdp))
            {
                Logger.LogInformation("Showing login: User is logged in with idp: {idp}, but idp not in client restriction list.", currentIdp);
                return Task.FromResult(new InteractionResponse { IsLogin = true });
            }

            // check client's user SSO timeout
            if (request.Client.UserSsoLifetime.HasValue)
            {
                long authTimeEpoch = user.GetAuthenticationTimeEpoch();
                long diff = Clock.UtcNow.ToUnixTimeSeconds() - authTimeEpoch;
                if (diff > request.Client.UserSsoLifetime.Value)
                {
                    Logger.LogInformation("Showing login: User's auth session duration: {sessionDuration} exceeds client's user SSO lifetime: {userSsoLifetime}.", diff, request.Client.UserSsoLifetime);
                    return Task.FromResult(new InteractionResponse { IsLogin = true });
                }
            }

            return Task.FromResult(new InteractionResponse());
        }

        /// <summary>
        /// Processes the consent logic.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="consent">The consent.</param>
        /// <returns>The interaction response.</returns>
        protected virtual Task<InteractionResponse> ProcessConsentAsync(ValidatedSaml2Request request, ConsentResponse consent = null)
        {
            return Task.FromResult(new InteractionResponse());
        }
    }
}