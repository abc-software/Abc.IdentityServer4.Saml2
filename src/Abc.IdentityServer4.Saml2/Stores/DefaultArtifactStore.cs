// ----------------------------------------------------------------------------
// <copyright file="DefaultArtifactStore.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Stores
{
    internal class DefaultArtifactStore : DefaultGrantStore<Saml2Response>, IArtifactStore
    {
        public DefaultArtifactStore(IPersistedGrantStore store, ILogger<DefaultArtifactStore> logger)
            : base("saml2_artifact", store, null, null, logger)
        {
        }

        /// <inheritdoc/>
        public Task StoreAsync(string key, string clientId, Saml2Response message, DateTime created, DateTime? expiration)
        {
            return this.StoreItemAsync(key, message, clientId, null, null, null, created, expiration);
        }

        /// <inheritdoc/>
        public async Task<Saml2ArtifactResponseContent> GetAsync(string key)
        {
            var hashedKey = this.GetHashedKey(key);
            var grant = await this.Store.GetAsync(hashedKey);
            if (grant != null && grant.Type == this.GrantType)
            {
                try
                {
                    return ToResponseContext(grant.Data);
                }
                catch (Exception ex)
                {
                    this.Logger.LogError(ex, "Failed to deserialize SAML2 response from grant store.");
                }
            }
            else
            {
                this.Logger.LogDebug("{grantType} grant with value: {key} not found in store.", this.GrantType, key);
            }

            return null;
        }

        /// <inheritdoc/>
        public Task RemoveAsync(string key)
        {
            return this.RemoveItemAsync(key);
        }

        /// <inheritdoc/>
        protected override async Task StoreItemAsync(string key, Saml2Response item, string clientId, string subjectId, string sessionId, string description, DateTime created, DateTime? expiration, DateTime? consumedTime = null)
        {
            key = GetHashedKey(key);
            
            var data = SamlResponseToString(item);

            var grant = new PersistedGrant
            {
                Key = key,
                Type = GrantType,
                ClientId = clientId,
                SubjectId = subjectId,
                SessionId = sessionId,
                Description = description,
                CreationTime = created,
                Expiration = expiration,
                ConsumedTime = consumedTime,
                Data = data,
            };

            await this.Store.StoreAsync(grant);
        }

        private static string SamlResponseToString(Saml2Response response)
        {
            var serializer = new Saml2ProtocolSerializer();
            using (var stringWriter = new System.IO.StringWriter())
            {
                using (var writer = System.Xml.XmlWriter.Create(stringWriter, new System.Xml.XmlWriterSettings() { OmitXmlDeclaration = true }))
                {
                    serializer.WriteSamlMessage(writer, response);
                }

                return stringWriter.ToString();
            }
        }

        private static Saml2ArtifactResponseContent ToResponseContext(string data)
        {
            var doc = new System.Xml.XmlDocument() { XmlResolver = null };
            doc.LoadXml(data);

            return new Saml2ArtifactResponseContent(doc.DocumentElement);
        }

        /*
        private class Saml2ArtifactPersistentGrantSerializer : IPersistentGrantSerializer
        {
            public T Deserialize<T>(string json)
            {
                var doc = new System.Xml.XmlDocument() { XmlResolver = null };
                doc.LoadXml(json);

                return (T)(object)new Saml2ArtifactResponseContent(doc.DocumentElement);
            }

            public string Serialize<T>(T value)
            {
                var serializer = new Saml2ProtocolSerializer();
                using (var stringWriter = new System.IO.StringWriter())
                {
                    using (var writer = System.Xml.XmlWriter.Create(stringWriter, new System.Xml.XmlWriterSettings() { OmitXmlDeclaration = true }))
                    {
                        serializer.WriteSamlMessage(writer, message);
                    }

                    return stringWriter.ToString();
                }
            }
        }
        */
    }
}