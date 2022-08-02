// ----------------------------------------------------------------------------
// <copyright file="IArtifactStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Abc.IdentityModel.Protocols.Saml2;

namespace Abc.IdentityServer4.Saml2.Stores
{
    /// <summary>
    /// The artifact store.
    /// </summary>
    internal interface IArtifactStore
    {
        /// <summary>
        /// Store the specified artifact to artifact store as an asynchronous operation.
        /// </summary>
        /// <param name="key">The artifact identifier.</param>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="message">The SAML2 message.</param>
        /// <param name="created">The created time.</param>
        /// <param name="expiration">The expiration.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task StoreAsync(string key, string clientId, Saml2Response message, DateTime created, DateTime? expiration);

        /// <summary>
        /// Gets the specified artifact from artifact storage by identifier as an asynchronous operation.
        /// </summary>
        /// <param name="key">The artifact identifier.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task<Saml2ArtifactResponseContent> GetAsync(string key);

        /// <summary>
        /// Remove the specified artifact form store by identifier as an asynchronous operation.
        /// </summary>
        /// <param name="key">The artifact identifier.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        Task RemoveAsync(string key);
    }
}