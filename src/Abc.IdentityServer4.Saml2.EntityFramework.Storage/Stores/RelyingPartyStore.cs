// ----------------------------------------------------------------------------
// <copyright file="RelyingPartyStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer.Saml2.EntityFramework.Interfaces;
using Abc.IdentityServer.Saml2.EntityFramework.Mappers;
using Abc.IdentityServer.Saml2.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer.Saml2.EntityFramework.Stores;

/// <summary>
/// Implementation of IClientStore and IRelyingPartyStore thats uses EF.
/// </summary>
/// <seealso cref="IClientStore" />
/// <seealso cref="IRelyingPartyStore" />
public class RelyingPartyStore : ClientStore, IRelyingPartyStore
{
#if IDS4
    /// <summary>
    /// Initializes a new instance of the <see cref="RelyingPartyStore"/> class.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="logger">The logger.</param>
    /// <exception cref="ArgumentNullException">if context is null.</exception>
    public RelyingPartyStore(ISaml2ConfigurationDbContext context, ILogger<RelyingPartyStore> logger) 
        : base(context, logger)
    {
    }
#endif
#if DUENDE
    /// <summary>
    /// Initializes a new instance of the <see cref="RelyingPartyStore"/> class.
    /// </summary>
    /// <param name="context">The context.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="cancellationTokenProvider">The cancelation token provider.</param>
    /// <exception cref="ArgumentNullException">if context is null.</exception>
    public RelyingPartyStore(ISaml2ConfigurationDbContext context, ILogger<RelyingPartyStore> logger, ICancellationTokenProvider cancellationTokenProvider)
        : base(context, logger, cancellationTokenProvider)
    {
    }
#endif

    /// <summary>
    /// Gets the DbContext.
    /// </summary>
    protected new ISaml2ConfigurationDbContext Context { get => (ISaml2ConfigurationDbContext)base.Context; }

    /// <inheritdoc/>
    public async Task<RelyingParty> FindRelyingPartyByEntityIdAsync(string entityId)
    {
        var query = Context.Clients
            .Where(x => x.ClientId == entityId)
            .Join(Context.Saml2RelyingParties.Include(c => c.ValidationCertificate).Include(c => c.EncryptionCertificate), x => x.Id, y => y.ClientId, (c, rp) =>
            new Entities.RelyingParty
            {
                EntityId = c.ClientId,
                DigestAlgorithm = rp.DigestAlgorithm,
                SignatureAlgorithm = rp.SignatureAlgorithm,
                EncryptionAlgorithm = rp.EncryptionAlgorithm,
                KeyWrapAlgorithm = rp.KeyWrapAlgorithm,
                NameIdentifierFormat = rp.NameIdentifierFormat,
                FrontChannelLogoutBinding = rp.FrontChannelLogoutBinding,
                IncludeSubjectConfirmationDataNotBefore = rp.IncludeSubjectConfirmationDataNotBefore,   
                SignAssertion = rp.SignAssertion,

                ClaimMappings = rp.ClaimMappings,
                EncryptionCertificate = rp.EncryptionCertificate,
                ValidationCertificate = rp.ValidationCertificate,

                // UNDONE: move to servies table
                SingleSignOnBinding = rp.SingleSignOnBinding,
                ArtifactResolutionUri = rp.ArtifactResolutionUri,
                SingleSignOnUri = rp.SingleSignOnUri,
            })
            .AsNoTracking()
#if NET5_0_OR_GREATER && !IDS4
            .AsSplitQuery()
#endif
            ;

        var relyingParty = (await query.ToArrayAsync(
#if DUENDE
            CancellationTokenProvider.CancellationToken
#endif
            ))
            .SingleOrDefault(x => x.EntityId == entityId);
        if (relyingParty == null)
        {
            return null;
        }

        return relyingParty.ToModel();
    }
}