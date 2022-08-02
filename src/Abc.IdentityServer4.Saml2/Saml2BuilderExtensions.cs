// ----------------------------------------------------------------------------
// <copyright file="Saml2BuilderExtensions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2;
using Abc.IdentityServer4.Saml2.Endpoints;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Services;
using Abc.IdentityServer4.Saml2.Stores;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class Saml2BuilderExtensions
    {
        public static IIdentityServerBuilder AddSaml2(this IIdentityServerBuilder builder)
        {
            return AddSaml2<NoRelyingPartyStore>(builder);
        }

        public static IIdentityServerBuilder AddSaml2<TStore>(this IIdentityServerBuilder builder)
            where TStore : class, IRelyingPartyStore
        {
            builder.Services.AddTransient<IMetadataResponseGenerator, MetadataResponseGenerator>();
            builder.Services.AddTransient<ISignInResponseGenerator, SignInResponseGenerator>();
            builder.Services.AddTransient<ISaml2RequestValidator, Saml2RequestValidator>();
            builder.Services.AddTransient<ISignInInteractionResponseGenerator, SignInInteractionResponseGenerator>();
            //builder.Services.AddTransient<ISignOutValidator, SignOutValidator>();
            builder.Services.AddTransient<IClaimsService, DefaultClaimsService>();
            builder.Services.AddTransient<IdentityServer4.Services.IReturnUrlParser, Saml2ReturnUrlParser>();

            // to support federated logout, use iframe, only redirect binding support
            //builder.Services.Decorate<IdentityServer4.Services.ILogoutNotificationService, LogoutNotificationService>();
            // _OR_
            // to support federated logout, use iframe 
            builder.Services.AddTransient<ISaml2LogoutNotificationService, Saml2LogoutNotificationService>();
            builder.Services.Decorate<IdentityServer4.Services.IIdentityServerInteractionService, Saml2IdentityServerInteractionService>();

            builder.Services.AddTransient<ILogoutRequestGenerator, LogoutRequestGenerator>();
            builder.Services.AddTransient<ILogoutResponseGenerator, LogoutResponseGenerator>();

            builder.Services.TryAddTransient<IRelyingPartyStore, TStore>();

            builder.Services.AddTransient<IArtifactStore, DefaultArtifactStore>();

            builder.Services.AddTransient<Abc.IdentityModel.Protocols.Saml2.ISaml2TokenToSerializerAdaptor, Abc.IdentityModel.Protocols.Saml2.Saml2TokenToSerializerAdaptor>();
            builder.Services.AddTransient(s =>
            {
                var adaptor = s.GetRequiredService<Abc.IdentityModel.Protocols.Saml2.ISaml2TokenToSerializerAdaptor>();
                var options = s.GetRequiredService<IOptions<Saml2SPOptions>>().Value;
                var tokenValidationParameters = options.TokenValidationParameters;

                // UNDONE: disabled signature validation
                tokenValidationParameters = null;

                return new Abc.IdentityModel.Protocols.Saml2.HttpSaml2MessageSerializer(new Abc.IdentityModel.Protocols.Saml2.Saml2ProtocolSerializer(tokenValidationParameters, adaptor, null), tokenValidationParameters);
            });

            builder.Services.AddSingleton(
                resolver => resolver.GetRequiredService<IOptions<Saml2SPOptions>>().Value);

            builder.AddEndpoint<Saml2SingleSignOnEndpoint>(Constants.EndpointNames.SingleSignOn, Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash());
            //builder.AddEndpoint<Saml2SingleSignOnEndpoint>(Constants.EndpointNames.Saml2Callback, Constants.ProtocolRoutePaths.Saml2Callback.EnsureLeadingSlash());
            builder.AddEndpoint<Saml2MetadataEndpoint>(Constants.EndpointNames.Metadata, Constants.ProtocolRoutePaths.Metadata.EnsureLeadingSlash());
            builder.AddEndpoint<Saml2ArtifactResolutionEndpoint>(Constants.EndpointNames.ArtefactResolutionService, Constants.ProtocolRoutePaths.ArtefactResolutionService.EnsureLeadingSlash());
            builder.AddEndpoint<EndSessionCallbackEndpoint>(Constants.EndpointNames.SingleLogoutServiceCallback, Constants.ProtocolRoutePaths.SingleLogoutServiceCallback.EnsureLeadingSlash());

            return builder;
        }

        public static IIdentityServerBuilder AddSaml2(this IIdentityServerBuilder builder, Action<Saml2SPOptions> setupAction)
        {
            builder.Services.Configure(setupAction);
            return builder.AddSaml2();
        }

        public static IIdentityServerBuilder AddSaml2(this IIdentityServerBuilder builder, IConfiguration configuration)
        {
            builder.Services.Configure<Saml2SPOptions>(configuration);
            return builder.AddSaml2();
        }

        public static IIdentityServerBuilder AddInMemoryRelyingParties(this IIdentityServerBuilder builder, IEnumerable<RelyingParty> relyingParties)
        {
            builder.Services.AddSingleton(relyingParties);
            builder.Services.AddSingleton<IRelyingPartyStore, InMemoryRelyingPartyStore>();
            return builder;
        }
    }
}