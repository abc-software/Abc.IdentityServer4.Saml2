// ----------------------------------------------------------------------------
// <copyright file="Saml2SPOptions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Abc.IdentityServer4.Saml2
{
    /// <summary>
    /// The options for the service provider's behavior.
    /// </summary>
    public class Saml2SPOptions
    {
        /// <summary>
        /// Gets or sets the default digest algorithm.
        /// </summary>
        /// <value>
        /// The default digest algorithm.
        /// </value>
        public string DefaultDigestAlgorithm { get; set; } = SecurityAlgorithms.Sha256Digest;

        /// <summary>
        /// Gets or sets the default signature algorithm.
        /// </summary>
        /// <value>
        /// The default signature algorithm.
        /// </value>
        public string DefaultSignatureAlgorithm { get; set; } = SecurityAlgorithms.RsaSha256Signature;

        /// <summary>
        /// Gets or sets the name identifier format.
        /// </summary>
        /// <value>
        /// The name identifier format.
        /// </value>
        public string DefaultNameIdentifierFormat { get; set; } = Saml2Constants.NameIdentifierFormats.Unspecified.OriginalString; // TODO: saml2 constants

        /// <summary>
        /// Gets or sets the default encryption algorithm.
        /// </summary>
        /// <value>
        /// The default encryption algorithm.
        /// </value>
        public string DefaultEncryptionAlgorithm { get; set; } = SecurityAlgorithms.Aes256Encryption;

        /// <summary>
        /// Gets or sets the default key wrap algorithm.
        /// </summary>
        /// <value>
        /// The default key wrap algorithm.
        /// </value>
        public string DefaultKeyWrapAlgorithm { get; set; } = SecurityAlgorithms.RsaOaepKeyWrap;

        public bool WantAuthenticationRequestsSigned { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether sign assertion.
        /// </summary>
        /// <value>
        ///   <c>true</c> if sign assertion; otherwise, <c>false</c>.
        /// </value>
        public bool SignAssertion{ get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether include in subject confirmation data not before date.
        /// </summary>
        /// <value>
        ///   <c>true</c> if include in subject confirmation data not before date; otherwise, <c>false</c>.
        /// </value>
        public bool IncludeSubjectConfirmationDataNotBefore { get; set; } = false;

        //public bool RequireSignedLogoutResponses { get; set; }
        //public bool RequireSignedLogoutRequests { get; set; }

        /// <summary>
        /// Gets or sets the message lifetime.
        /// </summary>
        /// <value>
        /// The message lifetime.
        /// </value>
        public TimeSpan MessageLifetime { get; set; } = TimeSpan.FromMinutes(5.0);

        public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();
        public List<X509Certificate2> ValidationCertificates { get; set; } = new List<X509Certificate2>();

        /// <summary>
        /// Gets or sets the security token handler used to write <see cref="Saml2SecurityToken"/>.
        /// </summary>
        public Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler SecurityTokenHandler { get; set; } = new Microsoft.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler();

        /// <summary>
        /// Gets or sets the default claim mapping.
        /// </summary>
        /// <value>
        /// The default claim mapping.
        /// </value>
        public IDictionary<string, string> DefaultClaimMapping { get; set; } = new Dictionary<string, string>()
        {
            { JwtClaimTypes.Name, ClaimTypes.Name },
            { JwtClaimTypes.Subject, ClaimTypes.NameIdentifier },
            { JwtClaimTypes.Email, ClaimTypes.Email },
            { JwtClaimTypes.GivenName, ClaimTypes.GivenName },
            { JwtClaimTypes.FamilyName, ClaimTypes.Surname },
            { JwtClaimTypes.BirthDate, ClaimTypes.DateOfBirth },
            { JwtClaimTypes.WebSite, ClaimTypes.Webpage },
            { JwtClaimTypes.Gender, ClaimTypes.Gender },
            { JwtClaimTypes.Role, ClaimTypes.Role },
        };
    }
}