// ----------------------------------------------------------------------------
// <copyright file="RelyingPartyCertificate.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;

namespace Abc.IdentityServer.Saml2.EntityFramework.Entities;

/// <summary>
/// The certificate of the relying party.
/// </summary>
public class RelyingPartyCertificate
{
    /// <summary>
    /// Gets or sets the relying parties of the certificate.
    /// </summary>
    public virtual ICollection<RelyingParty> RelyingParties { get; set; }

    /// <summary>
    /// Gets or sets the primary key for this relying party certificate.
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Gets or sets the name of the certificate.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Gets or sets the name of the certificate authority that issued the certificate.
    /// </summary>
    public string Issuer { get; set; }

    /// <summary>
    /// Gets or sets the subject distinguished of the certificate.
    /// </summary>
    public string Subject { get; set; }

    /// <summary>
    /// Gets or sets the date in local time on which a certificate becomes valid.
    /// </summary>
    public DateTime NotBefore { get; set; }

    /// <summary>
    /// Gets or sets the date in local time after which a certificate is no longer valid.
    /// </summary>

    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Gets or sets the thumbprint of a certificate.
    /// </summary>
    public byte[] Thumbrint { get; set; }

    /// <summary>
    /// Gets or sets the raw X.509 public data of a certificate.
    /// </summary>
    public byte[] RawData { get; set; }
}