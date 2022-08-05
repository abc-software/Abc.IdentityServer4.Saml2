// ----------------------------------------------------------------------------
// <copyright file="Saml2SingleSignOnCallbackEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

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
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2SingleSignOnCallbackEndpoint : Saml2SingleSignOnEndpointBase
    {
        private readonly IConsentMessageStore _consentResponseStore;
        private readonly IAuthorizationParametersMessageStore _authorizationParametersMessageStore;

        public Saml2SingleSignOnCallbackEndpoint(
            IUserSession userSession,
            ILogger<Saml2SingleSignOnCallbackEndpoint> logger,
            ISignInResponseGenerator generator,
            ISignInInteractionResponseGenerator interaction,
            ISaml2RequestValidator signinValidator,
            IConsentMessageStore consentResponseStore,
            IAuthorizationParametersMessageStore authorizationParametersMessageStore,
            Saml2SPOptions options,
            IEventService events)
            : base(userSession, logger, generator, interaction, signinValidator, options, events)
        {
            _consentResponseStore = consentResponseStore;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
        }

        public override async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            Logger.LogDebug("Start SAML2 authentication callback request");

            if (!HttpMethods.IsGet(context.Request.Method))
            {
                Logger.LogWarning("Invalid HTTP method for SAML2 authentication callback endpoint.");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            var messageStoreId = context.Request.Query[Constants.DefaultRoutePathParams.MessageStoreIdParameterName];
            var data = await _authorizationParametersMessageStore.ReadAsync(messageStoreId);
            await _authorizationParametersMessageStore.DeleteAsync(messageStoreId);

            if (data?.Data == null)
            {
                return await CreateSignInErrorResult("SAML2 message is missing data.");
            }

            var requestMessage = data.Data.ToSaml2Message() as HttpSaml2RequestMessage2;
            if (!(requestMessage?.Saml2Request is Saml2AuthenticationRequest authenticationRequest))
            {
                return await CreateSignInErrorResult("SAML2 message is not authentication request.");
            }

            // user can be null here (this differs from HttpContext.User where the anonymous user is filled in)
            var user = await UserSession.GetUserAsync();

            var parameters = new NameValueCollection();
            parameters.Add(OidcConstants.AuthorizeRequest.ClientId, authenticationRequest.Issuer.Value);
            parameters.Add(OidcConstants.AuthorizeRequest.Nonce, authenticationRequest.Id.Value);
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

                Logger.LogTrace("End SAML2 authentication callback request. Result type: {0}", result?.GetType().ToString() ?? "-none-");

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
    }
}