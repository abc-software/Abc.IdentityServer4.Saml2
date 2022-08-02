// ----------------------------------------------------------------------------
// <copyright file="Saml2ReturnUrlParser.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2
{
    /// <summary>
    /// Parses a return URL using all registered URL parsers.
    /// </summary>
    public class Saml2ReturnUrlParser : IReturnUrlParser
    {
        private readonly ILogger _logger;
        private readonly ISaml2RequestValidator _signinValidator;
        private readonly IUserSession _userSession;
        private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2ReturnUrlParser"/> class.
        /// </summary>
        /// <param name="userSession">The user session.</param>
        /// <param name="signinValidator">The signin validator.</param>
        /// <param name="logger">The logger.</param>
        /// <param name="authorizationParametersMessageStore">The authorization parameters message store.</param>
        public Saml2ReturnUrlParser(
            IUserSession userSession,
            ISaml2RequestValidator signinValidator,
            ILogger<Saml2ReturnUrlParser> logger,
            IAuthorizationParametersMessageStore authorizationParametersMessageStore)
        {
            _signinValidator = signinValidator;
            _userSession = userSession;
            _logger = logger;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
        }

        /// <inheritdoc/>
        public bool IsValidReturnUrl(string returnUrl)
        {
            if (returnUrl != null && returnUrl.IsLocalUrl())
            {
                var index = returnUrl.IndexOf('?');
                if (index >= 0)
                {
                    returnUrl = returnUrl.Substring(0, index);
                }

                if ((returnUrl.EndsWith(Constants.ProtocolRoutePaths.SingleSignOn, StringComparison.Ordinal)
                    || returnUrl.EndsWith(Constants.ProtocolRoutePaths.SigleSignOnCallback, StringComparison.Ordinal))
                    && index >= 0)
                {
                    _logger.LogTrace("SAML2 - returnUrl is valid");
                    return true;
                }
            }

            _logger.LogTrace("SAML2 - returnUrl is not valid");
            return false;
        }

        /// <inheritdoc/>
        public async Task<AuthorizationRequest> ParseAsync(string returnUrl)
        {
            if (!IsValidReturnUrl(returnUrl))
            {
                return null;
            }

            var signInMessage = await GetSignInRequestMessage(returnUrl);
            if (signInMessage == null)
            {
                return null;
            }

            var user = await _userSession.GetUserAsync();
            var result = await _signinValidator.ValidateAsync(signInMessage, user);
            if (result.IsError)
            {
                return null;
            }

            var validatedRequest = result.ValidatedRequest;
            var request = new AuthorizationRequest()
            {
                Client = validatedRequest.Client,
                IdP = validatedRequest.Saml2RequestMessage.Saml2Request.GetIdP(),
                Tenant = validatedRequest.Saml2RequestMessage.Saml2Request.GetTenant(),
                AcrValues = validatedRequest.Saml2RequestMessage.Saml2Request.GetAcrValues(),
                RedirectUri = validatedRequest.ReplyUrl,
                ValidatedResources = validatedRequest.ValidatedResources,
            };

            // parameters scope and nonce necessary for consent store
            //request.Parameters.Add("scope", validatedRequest.ValidatedResources.RawScopeValues.ToSpaceSeparatedString());
            request.Parameters.Add("nonce", validatedRequest.Saml2RequestMessage.Saml2Request.Id.Value);

            return request;
        }

        private async Task<HttpSaml2RequestMessage2> GetSignInRequestMessage(string returnUrl)
        {
            var index = returnUrl.IndexOf('?');
            if (index >= 0)
            {
                returnUrl = returnUrl.Substring(index);
            }

            var query = QueryHelpers.ParseNullableQuery(returnUrl);
            if (!query.ContainsKey(Constants.DefaultRoutePathParams.MessageStoreIdParameterName))
            {
                return null;
            }

            string messageStoreId = query[Constants.DefaultRoutePathParams.MessageStoreIdParameterName];
            var data = await _authorizationParametersMessageStore.ReadAsync(messageStoreId);

            return data.Data.ToSaml2Message() as HttpSaml2RequestMessage2;
        }
    }
}