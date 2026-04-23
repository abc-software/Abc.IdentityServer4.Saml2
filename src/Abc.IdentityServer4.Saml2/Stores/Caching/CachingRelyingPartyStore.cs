// ----------------------------------------------------------------------------
// <copyright file="CachingRelyingPartyStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Abc.IdentityServer.Saml2.Stores
{
    /// <summary>
    /// Cache decorator for IRelyingPartyStore.
    /// </summary>
    /// <typeparam name="T"><seealso cref="IRelyingPartyStore"/></typeparam>
    /// <seealso cref="IdentityServer4.WsFederation.Stores.IRelyingPartyStore"/>
    public class CachingRelyingPartyStore<T> : IRelyingPartyStore
        where T : IRelyingPartyStore
    {
        private readonly IdentityServerOptions _options;
        private readonly ICache<RelyingParty> _cache;
        private readonly IRelyingPartyStore _inner;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="CachingRelyingPartyStore{T}"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="inner">The inner.</param>
        /// <param name="cache">The cache.</param>
        /// <param name="logger">The logger.</param>
        public CachingRelyingPartyStore(IdentityServerOptions options, T inner, ICache<RelyingParty> cache, ILogger<CachingRelyingPartyStore<T>> logger)
        {
            _options = options;
            _inner = inner;
            _cache = cache;
            _logger = logger;
        }

        /// <summary>
        /// Finds a relying party by entity id.
        /// </summary>
        /// <param name="entityId">The entity id.</param>
        /// <returns>
        /// The relying party.
        /// </returns>
        public async Task<RelyingParty> FindRelyingPartyByEntityIdAsync(string entityId)
        {
            var relyingParty = await _cache.GetAsync(
                entityId,
                _options.Caching.ClientStoreExpiration,
                () => _inner.FindRelyingPartyByEntityIdAsync(entityId),
                _logger);

            return relyingParty;
        }
    }
}