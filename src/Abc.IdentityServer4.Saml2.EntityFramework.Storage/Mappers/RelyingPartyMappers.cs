// ----------------------------------------------------------------------------
// <copyright file="RelyingPartyMappers.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Abc.IdentityServer.Saml2.EntityFramework.Mappers;

/// <summary>
/// Extension methods to map to/from entity/model for relying party.
/// </summary>
public static class RelyingPartyMappers
{
    /// <summary>
    /// Maps an entity to a model.
    /// </summary>
    /// <param name="entity">The entity.</param>
    /// <returns>The model.</returns>
    public static Saml2.Stores.RelyingParty ToModel(this Entities.RelyingParty entity)
    {
        return entity == null ? null :
            new Saml2.Stores.RelyingParty
            {
                EntityId = entity.EntityId,
                DigestAlgorithm = entity.DigestAlgorithm,
                SignatureAlgorithm = entity.SignatureAlgorithm,
                EncryptionAlgorithm = entity.EncryptionAlgorithm,
                KeyWrapAlgorithm = entity.KeyWrapAlgorithm,
                NameIdentifierFormat = entity.NameIdentifierFormat,
                FrontChannelLogoutBinding = entity.FrontChannelLogoutBinding,
                IncludeSubjectConfirmationDataNotBefore = entity.IncludeSubjectConfirmationDataNotBefore,
                SignAssertion = entity.SignAssertion,

                ClaimMapping = entity.ClaimMappings.ToDictionary(m => m.FromClaimType, m => m.ToClaimType),
                EncryptionCertificate = entity.EncryptionCertificate != null ? new X509Certificate2(entity.EncryptionCertificate) : null,
                ValidationCertificate = entity.ValidationCertificate != null ? new X509Certificate2(entity.ValidationCertificate) : null,

                // UNDONE: move to services table
                SingleSignOnServices = new List<Saml2.Stores.Service>() { new Saml2.Stores.Service() { Location = entity.SingleSignOnUri, Binding = entity.SingleSignOnBinding } },
                ArtifactResolutionServices = new List<Saml2.Stores.Service>() { new Saml2.Stores.Service() { Location = entity.ArtifactResolutionUri, Binding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP" } },
            };
    }

    /// <summary>
    /// Maps a model to an entity.
    /// </summary>
    /// <param name="model">The model.</param>
    /// <returns>The entity.</returns>
    public static Entities.RelyingParty ToEntity(this Saml2.Stores.RelyingParty model)
    {
        if (model == null)
        {
            return null;
        }

        var entity = new Entities.RelyingParty
        {
            EntityId = model.EntityId,
            DigestAlgorithm = model.DigestAlgorithm,
            SignatureAlgorithm = model.SignatureAlgorithm,
            EncryptionAlgorithm = model.EncryptionAlgorithm,
            KeyWrapAlgorithm = model.KeyWrapAlgorithm,
            NameIdentifierFormat = model.NameIdentifierFormat,
            FrontChannelLogoutBinding = model.FrontChannelLogoutBinding,
            IncludeSubjectConfirmationDataNotBefore = model.IncludeSubjectConfirmationDataNotBefore,
            SignAssertion = model.SignAssertion,

            ClaimMappings = model.ClaimMapping?.Select(c => new Entities.RelyingPartyClaimMapping
            {
                FromClaimType = c.Key,
                ToClaimType = c.Value,
            }).ToList() ?? new List<Entities.RelyingPartyClaimMapping>(),

            EncryptionCertificate = model.EncryptionCertificate?.GetPublicKey(),
            ValidationCertificate = model.ValidationCertificate?.GetPublicKey(),
        };

        // UNDONE: move to services table
        var signleSignOnService = model.SingleSignOnServices?.FirstOrDefault();
        if (signleSignOnService != null)
        {
            entity.SingleSignOnUri = signleSignOnService.Location;
            entity.SingleSignOnBinding = signleSignOnService.Binding;
        }

        var artifactResolutionService = model.ArtifactResolutionServices?.FirstOrDefault();
        if (artifactResolutionService != null)
        {
            entity.ArtifactResolutionUri = artifactResolutionService.Location;
        }

        return entity;
    }
}