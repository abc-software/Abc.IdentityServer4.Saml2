// ----------------------------------------------------------------------------
// <copyright file="RelyingParty.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Abc.IdentityServer4.Saml2.Stores
{
    /// <summary>
    /// A service provider.
    /// </summary>
    public class RelyingParty
    {
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
        public X509Certificate2 EncryptionCertificate { get; set; }

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
        /// Gets or sets the front channel logout binding.
        /// </summary>
        /// <value>
        /// if <c>null</c> if use HTTP-Redirect binding.
        /// </value>
        public string FrontChannelLogoutBinding { get; set; }

        public X509Certificate2 ValidationCertificate { get; set; }

        public List<Service> SingleSignOnServices { get; set; } = new List<Service>();
        public List<Service> ArtifactResolutionServices { get; set; } = new List<Service>();

        /// <summary>
        /// Gets or sets the claim mapping.
        /// </summary>
        /// <value>
        /// The claim mapping.
        /// </value>
        public IDictionary<string, string> ClaimMapping { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether sign assertion.
        /// </summary>
        /// <value>
        ///   <c>null</c> if use default value <see cref="Saml2SPOptions"/>, <c>true</c> if sign assertion; otherwise, <c>false</c>.
        /// </value>
        public bool? SignAssertion { get; set; }
        //public bool? EncryptAssertions { get; set; } true if EncryptionCertificate != null
        //public bool? WantAuthenticationRequestsSigned { get; set; } true if ValidationCertificate != null

        /// <summary>
        /// Gets or sets a value indicating whether include in subject confirmation data not before date.
        /// </summary>
        /// <value>
        ///   <c>null</c> if use default value <see cref="Saml2SPOptions"/>, <c>true</c> if include in subject confirmation data not before date; otherwise, <c>false</c>.
        /// </value>
        public bool? IncludeSubjectConfirmationDataNotBefore { get; set; }
    }

    public class Service
    {
        public string Binding { get; set; }

        public string Location { get; set; }

        public int Index { get; set; }

        public bool IsDefault { get; set; }
    }
}