// ----------------------------------------------------------------------------
// <copyright file="RelyingPartyClaimMapping.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.ComponentModel.DataAnnotations;

namespace Abc.IdentityServer.Saml2.EntityFramework.Entities;

/// <summary>
/// 
/// </summary>
public class RelyingPartyClaimMapping
{
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the client table id.
    /// </summary>
    /// <value>
    /// The client table id.
    /// </value>
    public int ClientId { get; set; }

    /// <summary>
    /// Gets or sets the type of from claim.
    /// </summary>
    /// <value>
    /// The type of from claim.
    /// </value>
    [Required]
    public string FromClaimType { get; set; }

    /// <summary>
    /// Gets or sets the type of to claim.
    /// </summary>
    /// <value>
    /// The type of to claim.
    /// </value>
    [Required]
    public string ToClaimType { get; set; }

    /// <summary>
    /// Gets or sets the relying party.
    /// </summary>
    /// <value>
    /// The relying party.
    /// </value>
    public virtual RelyingParty RelyingParty { get; set; }
}