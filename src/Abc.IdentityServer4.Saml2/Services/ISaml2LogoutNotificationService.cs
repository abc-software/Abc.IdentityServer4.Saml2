// ----------------------------------------------------------------------------
// <copyright file="ISaml2LogoutNotificationService.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    public interface ISaml2LogoutNotificationService
    {
        public Task<IEnumerable<Saml2LogoutRequest>> GetFrontChannelLogoutNotificationsRequestsAsync(LogoutNotificationContext context);
    }

    public record Saml2LogoutRequest(string Payload, string Binding, string Origin);
}