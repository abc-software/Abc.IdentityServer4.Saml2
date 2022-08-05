// ----------------------------------------------------------------------------
// <copyright file="InMemoryRelyingPartyStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Stores
{
    /// <summary>
    /// In memory relying party store.
    /// </summary>
    /// <seealso cref="Abc.IdentityServer4.Saml2.Stores.IRelyingPartyStore" />
    public class InMemoryRelyingPartyStore : IRelyingPartyStore
    {
        private readonly IEnumerable<RelyingParty> _relyingParties;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryRelyingPartyStore"/> class.
        /// </summary>
        /// <param name="relyingParties">The relying parties.</param>
        public InMemoryRelyingPartyStore(IEnumerable<RelyingParty> relyingParties)
        {
            _relyingParties = relyingParties ?? throw new System.ArgumentNullException(nameof(relyingParties));

            if (_relyingParties.HasDuplicates(m => m.EntityId))
            {
                throw new ArgumentException("Relying parties must not contain duplicate entityIds", nameof(relyingParties));
            }
        }

        /// <inheritdoc/>
        public Task<RelyingParty> FindRelyingPartyByEntityIdAsync(string entityId)
        {
            return Task.FromResult(_relyingParties.FirstOrDefault(r => r.EntityId == entityId));
        }
    }
}