// ----------------------------------------------------------------------------
// <copyright file="LogoutRequestGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    internal class LogoutRequestGenerator : ILogoutRequestGenerator
    {
        private readonly ILogger _logger;
        private readonly Saml2SPOptions _options;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IKeyMaterialService _keys;
        private readonly ISystemClock _clock;

        public LogoutRequestGenerator(
            ILogger<LogoutResponseGenerator> logger,
            Saml2SPOptions options,
            IHttpContextAccessor contextAccessor,
            IKeyMaterialService keys,
            ISystemClock clock)
        {
            _logger = logger;
            _options = options;
            _contextAccessor = contextAccessor;
            _keys = keys;
            _clock = clock;
        }

        public async Task<HttpSaml2Message2> GenerateRequestAsync(Saml2RequestValidationResult validationResult)
        {
            _logger.LogDebug("Creating SAML2 signout request");

            var validatedRequest = validationResult.ValidatedRequest;

            var credentials = await _keys.GetX509SigningCredentialsAsync();
            var issuer = _contextAccessor.HttpContext.GetIdentityServerIssuerUri();
            var issueInstant = _clock.UtcNow.UtcDateTime;

            var signingCredentials = new SigningCredentials(
                credentials.Key,
                validatedRequest.RelyingParty?.SignatureAlgorithm ?? _options.DefaultSignatureAlgorithm,
                validatedRequest.RelyingParty?.DigestAlgorithm ?? _options.DefaultDigestAlgorithm);

            var singleSignOutService = validationResult.ValidatedRequest.RelyingParty?.SingleLogoutServices.FirstOrDefault();
            var destination = singleSignOutService?.Location ?? validatedRequest.ReplyUrl;
            var participant = validatedRequest.SessionParticipant;

            var nameId = new Saml2NameIdentifier(validatedRequest.Subject.GetSubjectId())
            {
                Format = participant?.NameIdentifierFormat,
                NameQualifier = participant?.NameIdentifierNameQualifier,
                SPNameQualifier = participant?.NameIdentifierSPNameQualifier,
                SPProvidedId = participant?.NameIdentifierSPProvided,
            };

            var logoutRequest = new Saml2LogoutRequest(nameId)
            {
                Issuer = new Saml2NameIdentifier(issuer),
                SigningCredentials = signingCredentials,
                IssueInstant = issueInstant,
                Destination = new Uri(destination),
                NotOnOrAfter = issueInstant + _options.MessageLifetime,
                Reason = Abc.IdentityModel.Protocols.Saml2.Saml2Constants.LogoutReasons.User.AbsoluteUri,
            };

            if (participant != null && participant.SessionIndex.IsPresent())
            {
                logoutRequest.SessionIndex.Add(participant.SessionIndex);
            }

            var method =
                string.Equals(singleSignOutService?.Binding, Abc.IdentityModel.Protocols.Saml2.Saml2Constants.ProtocolBindings.HttpPostString)
                ? HttpDeliveryMethods.PostRequest
                : HttpDeliveryMethods.GetRequest;
           
            return new HttpSaml2RequestMessage2(logoutRequest.Destination, logoutRequest, method)
            {
                //RelayState = validatedRequest.Saml2RequestMessage.RelayState,
            };
        }
    }
}