// ----------------------------------------------------------------------------
// <copyright file="Saml2ConfigurationStoreOptions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System;

namespace Abc.IdentityServer.Saml2.EntityFramework.Options;

/// <summary>
/// Options for configuring the configuration context.
/// </summary>
public class Saml2ConfigurationStoreOptions : ConfigurationStoreOptions
{
    /// <summary>
    /// Gets or sets the relying party table configuration.
    /// </summary>
    /// <value>
    /// The relying party.
    /// </value>
    public TableConfiguration RelyingParty { get; set; } = new TableConfiguration("RelyingParties");

    /// <summary>
    /// Gets or sets the relying party claim mapping table configuration.
    /// </summary>
    /// <value>
    /// The relying party claim mapping.
    /// </value>
    public TableConfiguration RelyingPartyClaimMapping { get; set; } = new TableConfiguration("RelyingPartyClaimMappings");

    /// <summary>
    /// Gets or sets the relying party service table configuration.
    /// </summary>
    /// <value>
    /// The relying party service.
    /// </value>
    public TableConfiguration RelyingPartyService { get; set; } = new TableConfiguration("RelyingPartyServices");

    /// <summary>
    /// Gets or sets the relying party certificate table configuration.
    /// </summary>
    /// <value>
    /// The relying party certificate.
    /// </value>
    public TableConfiguration RelyingPartyCertificate { get; set; } = new TableConfiguration("RelyingPartyCertificates");

    internal void Apply(ConfigurationStoreOptions storeOptions)
    {
        if (storeOptions is null)
        {
            throw new ArgumentNullException(nameof(storeOptions));
        }

        ConfigureDbContext = storeOptions.ConfigureDbContext;
        ResolveDbContextOptions = storeOptions.ResolveDbContextOptions;
        DefaultSchema = storeOptions.DefaultSchema;
#if DUENDE
        IdentityProvider = storeOptions.IdentityProvider;
        EnablePooling = storeOptions.EnablePooling;
        PoolSize = storeOptions.PoolSize;
#endif
        ApiResource = storeOptions.ApiResource;
        ApiResourceClaim = storeOptions.ApiResourceClaim;
        ApiResourceProperty = storeOptions.ApiResourceProperty;
        ApiResourceScope = storeOptions.ApiResourceScope;
        ApiResourceSecret = storeOptions.ApiResourceSecret;
        ApiScope = storeOptions.ApiScope;
        ApiScopeClaim = storeOptions.ApiScopeClaim;
        ApiScopeProperty = storeOptions.ApiScopeProperty;
        Client = storeOptions.Client;
        ClientClaim = storeOptions.ClientClaim;
        ClientCorsOrigin = storeOptions.ClientCorsOrigin;
        ClientGrantType = storeOptions.ClientGrantType;
        ClientIdPRestriction = storeOptions.ClientIdPRestriction;
        ClientPostLogoutRedirectUri = storeOptions.ClientPostLogoutRedirectUri;
        ClientProperty = storeOptions.ClientProperty;
        ClientRedirectUri = storeOptions.ClientRedirectUri;
        ClientScopes = storeOptions.ClientScopes;
        ClientSecret = storeOptions.ClientSecret;
        IdentityResource = storeOptions.IdentityResource;
        IdentityResourceClaim = storeOptions.IdentityResourceClaim;
        IdentityResourceProperty = storeOptions.IdentityResourceProperty;
    }
}