// ----------------------------------------------------------------------------
// <copyright file="RelyingPartyService.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.ComponentModel.DataAnnotations;

namespace Abc.IdentityServer.Saml2.EntityFramework.Entities;

public enum RelyingPartyServiceType
{
    SingleSignOnService,
    LogoutService,
    ArtifactResolutionService,
}

public class RelyingPartyService
{
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the client table id.
    /// </summary>
    /// <value>
    /// The client table id.
    /// </value>
    public int ClientId { get; set; }

    [Required]
    public RelyingPartyServiceType Type { get; set; }

    [Required]
    public int Index { get; set; }

    [Required]
    public bool IsDefault { get; set; }

    [Required]
    public string Location { get; set; }

    [Required]
    public string Binding { get; set; }

    /// <summary>
    /// Gets or sets the relying party.
    /// </summary>
    /// <value>
    /// The relying party.
    /// </value>
    public virtual RelyingParty RelyingParty { get; set; }
}