// ----------------------------------------------------------------------------
// <copyright file="ErrorPageResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    internal class ErrorPageResult : IEndpointResult
    {
        private IMessageStore<ErrorMessage> _errorMessageStore;
        private IdentityServerOptions _options;
        private ISystemClock _clock;

        public ErrorPageResult(string error, string errorDescription)
        {
            Error = error;
            ErrorDescription = errorDescription;
        }

        internal ErrorPageResult(string error, string errorDescription, IdentityServerOptions options, ISystemClock clock, IMessageStore<ErrorMessage> errorMessageStore)
            : this(error, errorDescription)
        {
            _options = options;
            _clock = clock;
            _errorMessageStore = errorMessageStore;
        }

        public string Error { get; }

        public string ErrorDescription { get; }

        public async Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            var errorMessage = new ErrorMessage
            {
                RequestId = context.TraceIdentifier,
                Error = Error,
                ErrorDescription = ErrorDescription,
            };

            var message = new Message<ErrorMessage>(errorMessage, _clock.UtcNow.UtcDateTime);
            var id = await _errorMessageStore.WriteAsync(message);

            var redirectUrl = _options.UserInteraction.ErrorUrl;
            redirectUrl = redirectUrl.AddQueryString(_options.UserInteraction.ErrorIdParameter, id);

            context.Response.RedirectToAbsoluteUrl(redirectUrl);
        }

        private void Init(HttpContext context)
        {
            _errorMessageStore ??= context.RequestServices.GetRequiredService<IMessageStore<ErrorMessage>>();
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
            _clock ??= context.RequestServices.GetRequiredService<ISystemClock>();
        }
    }
}