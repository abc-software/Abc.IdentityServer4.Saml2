// ----------------------------------------------------------------------------
// <copyright file="RelyingParty.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Collections.Generic;

namespace Abc.IdentityServer.Saml2.EntityFramework.Entities;

/// <summary>
/// Represents SAML2 relying party.
/// </summary>
public class RelyingParty
{
    /// <summary>
    /// Gets or sets the primary key for this relying party.
    /// </summary>
    public int ClientId { get; set; }

    /// <summary>
    /// Gets or sets the relying party client.
    /// </summary>
    public virtual IdsEntities.Client Client { get; set; }

    /// <summary>
    /// Gets or sets the entity identifier.
    /// </summary>
    /// <value>
    /// The entity identifier.
    /// </value>
    public string EntityId { get; set; }

    /// <summary>
    /// Gets or sets the signature digest.
    /// </summary>
    /// <value>
    /// The signature digest.
    /// </value>
    public string DigestAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the signature algorithm.
    /// </summary>
    /// <value>
    /// The signature algorithm.
    /// </value>
    public string SignatureAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the name identifier format.
    /// </summary>
    /// <value>
    /// The name identifier format.
    /// </value>
    public string NameIdentifierFormat { get; set; }

    /// <summary>
    /// Gets or sets the encryption certificate.
    /// </summary>
    /// <value>
    /// The encryption certificate.
    /// </value>
    public virtual RelyingPartyCertificate EncryptionCertificate { get; set; }

    /// <summary>
    /// Gets or sets the encryption algorithm.
    /// </summary>
    /// <value>
    /// The encryption algorithm.
    /// </value>
    public string EncryptionAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the key wrap algorithm.
    /// </summary>
    /// <value>
    /// The key wrap algorithm.
    /// </value>
    public string KeyWrapAlgorithm { get; set; }

    /// <summary>
    /// Gets or sets the claim mappings.
    /// </summary>
    /// <value>
    /// The claim mappings.
    /// </value>
    public virtual ICollection<RelyingPartyClaimMapping> ClaimMappings { get; set; }

    /// <summary>
    /// Gets or sets the front channel logout binding.
    /// </summary>
    /// <value>
    /// The front channel logout binding.
    /// </value>
    public string FrontChannelLogoutBinding { get; set; }

    /// <summary>
    /// Gets or sets the validation certificate.
    /// </summary>
    /// <value>
    /// The validation certificate.
    /// </value>
    public virtual RelyingPartyCertificate ValidationCertificate { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether include in subject confirmation data not before date.
    /// </summary>
    /// <value>
    /// The include in subject confirmation data not before date.
    /// </value>
    public bool? IncludeSubjectConfirmationDataNotBefore { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether sign assertion.
    /// </summary>
    /// <value>
    /// The sign assertion.
    /// </value>
    public bool? SignAssertion { get; set; }

    public string SingleSignOnUri { get; set; }
    public string SingleSignOnBinding { get; set; }
    public string ArtifactResolutionUri { get; set; }

    /* TODO:
    /// <summary>
    /// Gets or sets the services.
    /// </summary>
    /// <value>
    /// The services.
    /// </value>
    public virtual ICollection<RelyingPartyService> Services { get; set; }
    */
}