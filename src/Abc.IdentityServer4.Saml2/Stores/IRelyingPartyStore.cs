// ----------------------------------------------------------------------------
// <copyright file="IRelyingPartyStore.cs" company="ABC software Ltd">
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
    /// The relying party store.
    /// </summary>
    public interface IRelyingPartyStore
    {
        /// <summary>
        /// Finds the relying party by entity identifier as an asynchronous operation.
        /// </summary>
        /// <param name="entityId">The entity identifier.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task<RelyingParty> FindRelyingPartyByEntityId(string entityId);
    }
}