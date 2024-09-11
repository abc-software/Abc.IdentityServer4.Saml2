// ----------------------------------------------------------------------------
// <copyright file="Saml2ConfigurationStoreOptions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

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

}