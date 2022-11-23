// ----------------------------------------------------------------------------
// <copyright file="SignInResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    public class SignInResult : IEndpointResult
    {
        private IdentityServerOptions _options;
        private HttpSaml2MessageSerializer _serializer;

        public HttpSaml2Message2 Message { get; set; }

        public SignInResult(HttpSaml2Message2 message)
        {
            Message = message ?? throw new System.ArgumentNullException(nameof(message));
        }

        internal SignInResult(HttpSaml2Message2 message, HttpSaml2MessageSerializer serializer, IdentityServerOptions options)
            : this(message)
        {
            _serializer = serializer;
            _options = options;
        }

        public async Task ExecuteAsync(HttpContext context)
        {
            Init(context);

            // serializer do not add CSP header to post form
            if ((Message.HttpMethods & IdentityModel.Http.HttpDeliveryMethods.PostRequest) == IdentityModel.Http.HttpDeliveryMethods.PostRequest)
            {
                context.Response.AddSignInFormPostCspHeaders(_options.Csp, Message.BaseUri.AbsoluteUri.GetOrigin(), "sha256-veRHIN/XAFeehi7cRkeVBpkKTuAUMFxwA+NMPmu2Bec=", "sha256-goxCaq8/nQZDMumN+JWKJfmYH7cjYwLwwrQqkOF4W+o=");
            }

            await _serializer.SendMessageAsync(context.Response, Message);
        }

        private void Init(HttpContext context)
        {
            _serializer ??= context.RequestServices.GetRequiredService<HttpSaml2MessageSerializer>();
            _options ??= context.RequestServices.GetRequiredService<IdentityServerOptions>();
        }
    }
}