// ----------------------------------------------------------------------------
// <copyright file="Saml2IdentityServerInteractionService.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    internal class Saml2IdentityServerInteractionService : IIdentityServerInteractionService
    {
        private readonly IIdentityServerInteractionService _identityServerInteraction;
        private readonly IHttpContextAccessor _context;
        private readonly IMessageStore<LogoutMessage> _logoutMessageStore;

        public Saml2IdentityServerInteractionService(
            IIdentityServerInteractionService identityServerInteraction,
            IHttpContextAccessor context,
            IMessageStore<LogoutMessage> logoutMessageStore)
        {
            _identityServerInteraction = identityServerInteraction;
            _context = context;
            _logoutMessageStore = logoutMessageStore;
        }

        public Task<string> CreateLogoutContextAsync()
        {
            return _identityServerInteraction.CreateLogoutContextAsync();
        }

        public Task DenyAuthorizationAsync(AuthorizationRequest request, AuthorizationError error, string errorDescription = null)
        {
            return _identityServerInteraction.DenyAuthorizationAsync(request, error, errorDescription);
        }

        public Task<IEnumerable<Grant>> GetAllUserGrantsAsync()
        {
            return _identityServerInteraction.GetAllUserGrantsAsync();
        }

        public Task<AuthorizationRequest> GetAuthorizationContextAsync(string returnUrl)
        {
            return _identityServerInteraction.GetAuthorizationContextAsync(returnUrl);
        }

        public Task<ErrorMessage> GetErrorContextAsync(string errorId)
        {
            return _identityServerInteraction.GetErrorContextAsync(errorId);
        }

        public async Task<LogoutRequest> GetLogoutContextAsync(string logoutId)
        {
            var msg = await _logoutMessageStore.ReadAsync(logoutId);
            return new LogoutRequest(await _context.HttpContext.GetIdentityServerSignoutFrameCallbackUrlAsync(msg?.Data), msg?.Data);
        }

        public Task GrantConsentAsync(AuthorizationRequest request, ConsentResponse consent, string subject = null)
        {
            return _identityServerInteraction.GrantConsentAsync(request, consent, subject);
        }

        public bool IsValidReturnUrl(string returnUrl)
        {
            return _identityServerInteraction.IsValidReturnUrl(returnUrl);
        }

        public Task RevokeTokensForCurrentSessionAsync()
        {
            return _identityServerInteraction.RevokeTokensForCurrentSessionAsync();
        }

        public Task RevokeUserConsentAsync(string clientId)
        {
            return _identityServerInteraction.RevokeUserConsentAsync(clientId);
        }
    }
}