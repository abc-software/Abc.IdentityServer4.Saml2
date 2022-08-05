// ----------------------------------------------------------------------------
// <copyright file="SignOutResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    public class SignOutResult : IEndpointResult
    {
        private readonly ValidatedSaml2Request _validatedRequest;
        private IdentityServerOptions _options;
        private IMessageStore<LogoutMessage> _logoutMessageStore;
        private IAuthorizationParametersMessageStore _authorizationParametersMessageStore;
        private ISystemClock _clock;

        public SignOutResult(ValidatedSaml2Request validatedRequest)
        {
            _validatedRequest = validatedRequest ?? throw new System.ArgumentNullException(nameof(validatedRequest));
        }

        internal SignOutResult(ValidatedSaml2Request validatedRequest, IdentityServerOptions options, ISystemClock clock, IMessageStore<LogoutMessage> logoutMessageStore, IAuthorizationParametersMessageStore authorizationParametersMessageStore) 
            : this(validatedRequest)
        {
            _options = options;
            _logoutMessageStore = logoutMessageStore;
            _clock = clock;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
        }

        public async Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            var returnUrl = context.GetIdentityServerBaseUrl() + Constants.ProtocolRoutePaths.SingleLogoutServiceCallback.EnsureLeadingSlash();
            {
                var msg = new Message<IDictionary<string, string[]>>(_validatedRequest.Saml2RequestMessage.ToDictionary(), _clock.UtcNow.UtcDateTime);
                var requestId = await _authorizationParametersMessageStore.WriteAsync(msg);
                returnUrl = returnUrl.AddQueryString(Constants.DefaultRoutePathParams.RequestIdParameterName, requestId);
            }

            var logoutMessage = new LogoutMessage()
            {
                ClientId = _validatedRequest.Client?.ClientId,
                ClientName = _validatedRequest.Client?.ClientName,
                SubjectId = _validatedRequest.Subject?.GetSubjectId(),
                SessionId = _validatedRequest.SessionId,
                ClientIds = _validatedRequest.ClientIds?.Where(c => ((Validation.Saml2SessionParticipant)c).ClientId != _validatedRequest.Client?.ClientId), // exclude initiator
                PostLogoutRedirectUri = returnUrl,
            };

            string id = null;
            if (logoutMessage.ClientId.IsPresent() || logoutMessage.ClientIds?.Any() == true)
            {
                var msg = new Message<LogoutMessage>(logoutMessage, _clock.UtcNow.UtcDateTime);
                id = await _logoutMessageStore.WriteAsync(msg);
            }

            var redirectUrl = _options.UserInteraction.LogoutUrl;
            if (id != null)
            {
                redirectUrl = redirectUrl.AddQueryString(_options.UserInteraction.LogoutIdParameter, id);
            }

            context.Response.RedirectToAbsoluteUrl(redirectUrl);
        }

        private void Init(HttpContext context)
        {
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
            _logoutMessageStore ??= context.RequestServices.GetRequiredService<IMessageStore<LogoutMessage>>();
            _authorizationParametersMessageStore ??= context.RequestServices.GetRequiredService<IAuthorizationParametersMessageStore>();
            _clock ??= context.RequestServices.GetRequiredService<ISystemClock>();
        }
    }
}