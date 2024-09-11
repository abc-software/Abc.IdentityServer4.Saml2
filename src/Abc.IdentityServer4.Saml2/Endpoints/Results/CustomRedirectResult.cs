// ----------------------------------------------------------------------------
// <copyright file="CustomRedirectResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer.Extensions;
using Abc.IdentityServer.Saml2.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Abc.IdentityServer.Saml2.Endpoints.Results
{
    internal class CustomRedirectResult : IEndpointResult
    {
        private readonly ValidatedSaml2Request _request;
        private readonly string _url;
        private IdentityServerOptions _options;
        private IClock _clock;
        private IServerUrls _urls;
        private IAuthorizationParametersMessageStore _authorizationParametersMessageStore;

        public CustomRedirectResult(ValidatedSaml2Request request, string url)
        {
            if (request is null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (url.IsMissing())
            {
                throw new ArgumentNullException(nameof(url));
            }

            _request = request;
            _url = url;
        }

        internal CustomRedirectResult(ValidatedSaml2Request request, string url, IdentityServerOptions options, IClock clock, IServerUrls urls, IAuthorizationParametersMessageStore authorizationParametersMessageStore = null)
            : this(request, url)
        {
            _options = options;
            _clock = clock;
            _urls = urls;
            _authorizationParametersMessageStore = authorizationParametersMessageStore;
        }

        public async Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            var returnUrl = _urls.BasePath.EnsureTrailingSlash() + Constants.ProtocolRoutePaths.SigleSignOnCallback;

            var msg = new Message<IDictionary<string, string[]>>(_request.Saml2RequestMessage.ToDictionary(), _clock.UtcNow.UtcDateTime);
            var id = await _authorizationParametersMessageStore.WriteAsync(msg);
            returnUrl = returnUrl.AddQueryString(Constants.DefaultRoutePathParams.MessageStoreIdParameterName, id);

            if (!_url.IsLocalUrl())
            {
                // this converts the relative redirect path to an absolute one if we're 
                // redirecting to a different server
                returnUrl = _urls.BaseUrl.EnsureTrailingSlash() + returnUrl.RemoveLeadingSlash();
            }

            var url = _url.AddQueryString(_options.UserInteraction.CustomRedirectReturnUrlParameter, returnUrl);
            context.Response.Redirect(_urls.GetAbsoluteUrl(url));
        }

        private void Init(HttpContext context)
        {
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
            _authorizationParametersMessageStore ??= context.RequestServices.GetRequiredService<IAuthorizationParametersMessageStore>();
            _urls ??= context.RequestServices.GetRequiredService<IServerUrls>();
            _clock ??= context.RequestServices.GetRequiredService<IClock>();
        }
    }
}