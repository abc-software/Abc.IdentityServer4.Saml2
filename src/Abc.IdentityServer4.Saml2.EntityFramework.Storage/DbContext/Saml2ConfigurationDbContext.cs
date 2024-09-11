// ----------------------------------------------------------------------------
// <copyright file="WsFedConfigurationDbContext.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer.Saml2.EntityFramework.Entities;
using Abc.IdentityServer.Saml2.EntityFramework.Extensions;
using Abc.IdentityServer.Saml2.EntityFramework.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System;

namespace Abc.IdentityServer.Saml2.EntityFramework.DbContext;

/// <summary>
/// DbContext for the IdentityServer configuration data.
/// </summary>
/// <seealso cref="Microsoft.EntityFrameworkCore.DbContext" />
/// <seealso cref="Saml2ConfigurationDbContext" />
public class Saml2ConfigurationDbContext : Saml2ConfigurationDbContext<Saml2ConfigurationDbContext>
{
#if IDS4
    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2ConfigurationDbContext"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <exception cref="ArgumentNullException">storeOptions</exception>
    public Saml2ConfigurationDbContext(DbContextOptions<Saml2ConfigurationDbContext> options, Saml2ConfigurationStoreOptions storeOptions)
        : base(options, storeOptions)
    {
    }
#endif
#if DUENDE
    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2ConfigurationDbContext"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <exception cref="ArgumentNullException">storeOptions</exception>
    public Saml2ConfigurationDbContext(DbContextOptions<Saml2ConfigurationDbContext> options)
        : base(options)
    {
    }
#endif
}

/// <summary>
/// DbContext for the IdentityServer configuration data.
/// </summary>
/// <seealso cref="Microsoft.EntityFrameworkCore.DbContext" />
/// <seealso cref="Saml2ConfigurationDbContext
public class Saml2ConfigurationDbContext<TContext> : ConfigurationDbContext<TContext>, Interfaces.ISaml2ConfigurationDbContext
    where TContext : Microsoft.EntityFrameworkCore.DbContext, IConfigurationDbContext, Interfaces.ISaml2ConfigurationDbContext
{
#if IDS4
    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2ConfigurationDbContext{TContext}"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <exception cref="ArgumentNullException">storeOptions</exception>
    public Saml2ConfigurationDbContext(DbContextOptions<TContext> options, Saml2ConfigurationStoreOptions storeOptions)
        : base(options, storeOptions)
    {
        this.StoreOptions = storeOptions;
    }

    /// <summary>
    /// Gets or sets the store options.
    /// </summary>
    public Options.Saml2ConfigurationStoreOptions StoreOptions { get; }
#endif
#if DUENDE
    /// <summary>
    /// Initializes a new instance of the <see cref="Saml2ConfigurationDbContext{TContext}"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <exception cref="ArgumentNullException">storeOptions</exception>
    public Saml2ConfigurationDbContext(DbContextOptions<TContext> options) 
        : base(options)
    {
    }

    /// <summary>
    /// Gets or sets the store options.
    /// </summary>
    public new Options.Saml2ConfigurationStoreOptions StoreOptions { 
        get => (Options.Saml2ConfigurationStoreOptions)base.StoreOptions; 
        set => base.StoreOptions = value; 
    }
#endif

    /// <summary>
    /// Gets or sets the relying parties.
    /// </summary>
    /// <value>
    /// The relying parties.
    /// </value>
    public DbSet<RelyingParty> Saml2RelyingParties { get; set; }

    /// <inheritdoc/>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
#if DUENDE
        if (StoreOptions is null)
        {
            StoreOptions = this.GetService<Saml2ConfigurationStoreOptions>();
            if (StoreOptions is null)
            {
                throw new ArgumentNullException(nameof(StoreOptions), "Saml2ConfigurationStoreOptions must be configured in the DI system.");
            }
        }
#endif

        base.OnModelCreating(modelBuilder);
        modelBuilder.ConfigureRelyingPartyContext(StoreOptions);
    }
}