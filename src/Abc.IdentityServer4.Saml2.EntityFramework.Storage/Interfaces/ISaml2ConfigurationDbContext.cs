// ----------------------------------------------------------------------------
// <copyright file="ISaml2ConfigurationDbContext.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer.Saml2.EntityFramework.Entities;
using Microsoft.EntityFrameworkCore;

namespace Abc.IdentityServer.Saml2.EntityFramework.Interfaces;

/// <summary>
/// Abstraction for the configuration context.
/// </summary>
/// <seealso cref="IConfigurationDbContext" />
public interface ISaml2ConfigurationDbContext : IConfigurationDbContext
{
    /// <summary>
    /// Gets or sets the relying parties.
    /// </summary>
    /// <value>
    /// The relying parties.
    /// </value>
    DbSet<RelyingParty> Saml2RelyingParties { get; set; }
}