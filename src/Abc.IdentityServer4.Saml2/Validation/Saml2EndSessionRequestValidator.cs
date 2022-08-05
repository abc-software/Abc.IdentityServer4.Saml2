// ----------------------------------------------------------------------------
// <copyright file="Saml2EndSessionRequestValidator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2.Services;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using System.Collections.Specialized;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Validation
{
    internal class Saml2EndSessionRequestValidator : ISaml2EndSessionRequestValidator
    {
        public Saml2EndSessionRequestValidator(
            ISaml2LogoutNotificationService logoutNotificationService, 
            IMessageStore<LogoutNotificationContext> endSessionMessageStore, 
            ILogger<Saml2EndSessionRequestValidator> logger)
        {
            LogoutNotificationService = logoutNotificationService;
            EndSessionMessageStore = endSessionMessageStore;
            Logger = logger;
        }

        public ISaml2LogoutNotificationService LogoutNotificationService { get; }
        public IMessageStore<LogoutNotificationContext> EndSessionMessageStore { get; }
        public ILogger Logger { get; }

        public async Task<Saml2EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters)
        {
            var result = new Saml2EndSessionCallbackValidationResult();

            var endSessionId = parameters[Constants.DefaultRoutePathParams.EndSessionCallback];
            var endSessionMessage = await EndSessionMessageStore.ReadAsync(endSessionId);
            if (endSessionMessage?.Data?.ClientIds?.Any() == true)
            {
                result.IsError = false;
                result.FrontChannelLogoutRequests = await LogoutNotificationService.GetFrontChannelLogoutNotificationsRequestsAsync(endSessionMessage.Data);
            }
            else
            {
                result.IsError = true;
                result.Error = "Failed to read end session callback message";
            }

            return result;
        }
    }
}