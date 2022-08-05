// ----------------------------------------------------------------------------
// <copyright file="NoRelyingPartyStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Stores
{
    /// <summary>
    /// No relaying party store.
    /// </summary>
    /// <seealso cref="Abc.IdentityServer4.Saml2.Stores.IRelyingPartyStore" />
    public class NoRelyingPartyStore : IRelyingPartyStore
    {
        /// <inheritdoc/>
        public Task<RelyingParty> FindRelyingPartyByEntityIdAsync(string entityId)
        {
            return Task.FromResult<RelyingParty>(null);
        }
    }
}