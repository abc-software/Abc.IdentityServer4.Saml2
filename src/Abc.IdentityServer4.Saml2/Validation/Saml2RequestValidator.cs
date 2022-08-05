// ----------------------------------------------------------------------------
// <copyright file="Saml2RequestValidator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Extensions;
using Abc.IdentityServer4.Saml2.Stores;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Saml2AuthenticationRequest = Abc.IdentityModel.Protocols.Saml2.Saml2AuthenticationRequest;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public class Saml2RequestValidator : ISaml2RequestValidator
    {
        private readonly ILogger _logger;
        private readonly IClientStore _clients;
        private readonly IUserSession _userSession;
        private readonly IRedirectUriValidator _uriValidator;
        private readonly IdentityServerOptions _options;
        private readonly ISystemClock _clock;
        private readonly IRelyingPartyStore _relyingParties;

        public Saml2RequestValidator(
            ILogger<Saml2RequestValidator> logger,
            IClientStore clients,
            IUserSession userSession,
            IRedirectUriValidator uriValidator,
            IdentityServerOptions options,
            ISystemClock clock,
            IRelyingPartyStore relyingParties)
        {
            _logger = logger;
            _clients = clients;
            _userSession = userSession;
            _uriValidator = uriValidator;
            _options = options;
            _clock = clock;
            _relyingParties = relyingParties;
        }

        public async Task<Saml2RequestValidationResult> ValidateAsync(HttpSaml2RequestMessage2 message, ClaimsPrincipal user)
        {
            var validatedResult = new ValidatedSaml2Request()
            {
                Options = _options,
                Saml2RequestMessage = message,
            };

            _logger.LogInformation("Start SAML2 request validation");

            // validate issuer
            var clientResult = await ValidateClientAsync(validatedResult);
            if (clientResult.IsError)
            {
                return clientResult;
            }

            // validate IssueInstant, Conditions.NotOnOrAfter, Conditions.NotBefore
            var optionalResult = ValidateParameters(validatedResult);
            if (optionalResult.IsError)
            {
                return optionalResult;
            }

            // check if additional relying party settings exist
            validatedResult.RelyingParty = await _relyingParties.FindRelyingPartyByEntityIdAsync(validatedResult.ClientId);

            // validate assertionConsumerServiceUrl
            var replyResult = await ValidateReplyAsync(validatedResult);
            if (replyResult.IsError)
            {
                return replyResult;
            }

            validatedResult.SessionId = await _userSession.GetSessionIdAsync();
            validatedResult.ClientIds = await _userSession.GetClientListAsync();
            validatedResult.Subject = user;

            await ValidateRequestedResourcesAsync(validatedResult);

            _logger.LogTrace("SAML2 request validation successful");

            return new Saml2RequestValidationResult(validatedResult);
        }

        protected virtual Task ValidateRequestedResourcesAsync(ValidatedSaml2Request validatedRequest)
        {
            var resourceValidationResult = new ResourceValidationResult();

            foreach (var item in validatedRequest.Client.AllowedScopes)
            {
                resourceValidationResult.ParsedScopes.Add(new ParsedScopeValue(item));
            }

            validatedRequest.ValidatedResources = resourceValidationResult;
            return Task.CompletedTask;
        }

        private async Task<Saml2RequestValidationResult> ValidateReplyAsync(ValidatedSaml2Request request)
        {
            var saml2Request = request.Saml2RequestMessage?.Saml2Request;
            if (saml2Request is null)
            {
                return new Saml2RequestValidationResult(request, "invalid_request", "Missing request");
            }

            var client = request.Client;

            if (saml2Request is Saml2AuthenticationRequest authRequest)
            {
                var assertionConsumerServiceUrl = authRequest.AssertionConsumerServiceUrl;
                var protocolBinding = authRequest.ProtocolBinding;
                var assertionConsumerServiceIndex = authRequest.AssertionConsumerServiceIndex;

                // Validate AssertionConsumerServiceUrl, ProtocolBinding, AssertionConsumerServiceIndex
                // TODO: ProtocolBinding + AssertionConsumerServiceIndex
                if (assertionConsumerServiceUrl != null)
                {
                    // assertionConsumerServiceUrl must be valid URI
                    if (!assertionConsumerServiceUrl.IsAbsoluteUri)
                    {
                        return new Saml2RequestValidationResult(request, "invalid_request", $"AssertionConsumerServiceUrl '{assertionConsumerServiceUrl}' is not absolute URI");
                    }

                    if (assertionConsumerServiceUrl.OriginalString.IsMissingOrTooLong(_options.InputLengthRestrictions.RedirectUri))
                    {
                        return new Saml2RequestValidationResult(request, "invalid_request", "Invalid reply URI");
                    }

                    if (await _uriValidator.IsRedirectUriValidAsync(authRequest.AssertionConsumerServiceUrl.AbsoluteUri, client))
                    {
                        request.ReplyUrl = authRequest.AssertionConsumerServiceUrl.AbsoluteUri;
                    }
                    else
                    {
                        _logger.LogWarning("Invalid AssertionConsumerServiceUrl: {AssertionConsumerServiceUrl}", authRequest.AssertionConsumerServiceUrl);
                    }
                }
                
                /* TODO:
                if (protocolBinding != null)
                {
                    var service = request.RelyingParty?.SingleSignOnServices.Find(s => s.Binding == protocolBinding.OriginalString);
                    if (service != null)
                    {
                        request.ReplyUrl = service.Location;
                    }
                }

                if (assertionConsumerServiceIndex != null)
                {
                    var service = request.RelyingParty?.SingleSignOnServices.Find(s => s.Index == assertionConsumerServiceIndex.Value);
                    if (service != null)
                    {
                        request.ReplyUrl = service.Location;
                    }
                }
                */

                if (request.ReplyUrl == null)
                {
                    request.ReplyUrl = client.RedirectUris.FirstOrDefault();
                }
            }
            else if (saml2Request is Saml2LogoutRequest logoutRequest)
            {
                // TODO: logoutRequest.Reason

                request.ReplyUrl = client.PostLogoutRedirectUris.FirstOrDefault();
            }

            if (request.ReplyUrl == null)
            {
                return new Saml2RequestValidationResult(request, "invalid_relying_party", "No redirect URL configured for relying party");
            }

            return new Saml2RequestValidationResult(request);
        }

        private Saml2RequestValidationResult ValidateParameters(ValidatedSaml2Request request)
        {
            var saml2Request = request.Saml2RequestMessage?.Saml2Request;
            if (saml2Request is null)
            {
                return new Saml2RequestValidationResult(request, "invalid_request", "Missing issuer");
            }

            // IssueInstant
            var issueInstant = saml2Request.IssueInstant;
            var now = _clock.UtcNow.UtcDateTime;
            if (issueInstant.InFuture(now, 300) || issueInstant.InPast(now, 300)) // TODO: TimeTolerance from config
            {
                return new Saml2RequestValidationResult(request, "invalid_request", "IssueInstant time is in past or future");
            }

            // TODO: Destination

            var client = request.Client;

            if (saml2Request is Saml2AuthenticationRequest authRequest)
            {
                // NotOnOrAfter, NotBefore
                var conditions = authRequest.Conditions;
                if (conditions != null)
                {
                    if (conditions.NotOnOrAfter.HasValue && conditions.NotOnOrAfter.Value.InPast(now, 300)) // TODO: TimeTolerance from config
                    {
                        return new Saml2RequestValidationResult(request, "invalid_request", "NotOnOrAfter time is in past");
                    }

                    if (conditions.NotBefore.HasValue && conditions.NotBefore.Value.InFuture(now, 300)) // TODO: TimeTolerance from config
                    {
                        return new Saml2RequestValidationResult(request, "invalid_request", "NotBefore time is in future");
                    }
                }

                // RequestedAuthenticationContext
                var idp = authRequest.GetIdP();
                if (idp != null && client.IdentityProviderRestrictions != null
                    && client.IdentityProviderRestrictions.Any()
                    && !client.IdentityProviderRestrictions.Contains(idp))
                {
                    // exclude Idp RequestedAuthenticationContext from processing
                    authRequest.RemoveIdP();
                    _logger.LogWarning($"RequestedAuthnContext (idp) requested '{idp}' is not in client restriction list.");
                }
            }
            else if (saml2Request is Saml2LogoutRequest logoutRequest)
            {
                if (logoutRequest.NotOnOrAfter.HasValue && logoutRequest.NotOnOrAfter.Value.InPast(now, 300)) // TODO: TimeTolerance from config
                {
                    return new Saml2RequestValidationResult(request, "invalid_request", "NotOnOrAfter time is in past");
                }
            }

            return new Saml2RequestValidationResult(request);
        }

        private async Task<Saml2RequestValidationResult> ValidateClientAsync(ValidatedSaml2Request request)
        {
            var saml2Request = request.Saml2RequestMessage?.Saml2Request;
            if (saml2Request?.Issuer is null)
            {
                return new Saml2RequestValidationResult(request, "invalid_request", "Missing issuer");
            }

            var entityId = saml2Request.Issuer.Value;

            // entityId parameter must be present
            if (entityId.IsMissingOrTooLong(_options.InputLengthRestrictions.ClientId))
            {
                return new Saml2RequestValidationResult(request, "invalid_request", "Invalid issuer");
            }

            request.ClientId = entityId;

            // check for valid client
            var client = await _clients.FindEnabledClientByIdAsync(entityId);
            if (client == null)
            {
                return new Saml2RequestValidationResult(request, "invalid_relying_party", "Cannot find Client configuration");
            }

            if (client.ProtocolType != IdentityServerConstants.ProtocolTypes.Saml2p)
            {
                return new Saml2RequestValidationResult(request, "invalid_relying_party", "Client is not configured for SAML2");
            }

            request.SetClient(client);

            return new Saml2RequestValidationResult(request);
        }
    }
}