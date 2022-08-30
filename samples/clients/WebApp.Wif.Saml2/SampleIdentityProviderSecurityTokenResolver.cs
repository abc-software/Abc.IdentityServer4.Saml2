//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------

using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace Samples.Saml.Utilities
{
    /// <summary>
    /// The <c>SampleIdentityProviderSecurityTokenResolver</c> provides the ability to resolve the private key of an
    /// X.509 certificate without registering the X.509 certificate in the certificate store.
    /// </summary>
    public class SampleIdentityProviderSecurityTokenResolver : SecurityTokenResolver
    {
        SecurityTokenResolver _wrappedResolver;

        /// <summary>
        /// Initializes a new instance of the SampleIdentityProviderSecurityTokenResolver class.
        /// </summary>
        public SampleIdentityProviderSecurityTokenResolver()
        {
            SecurityToken myToken = CertificateUtility.GetIdentityProviderSigningToken( true );

            ReadOnlyCollection<SecurityToken> tokens = new ReadOnlyCollection<SecurityToken>(
                new SecurityToken[] { myToken } );
            _wrappedResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver( tokens, false );
        }

        /// <summary>
        /// Attempts to retrieve the key that is referenced in the specified key identifier clause.
        /// </summary>
        /// <param name="keyIdentifierClause">A SecurityKeyIdentifierClause to retrieve the key for.</param>
        /// <param name="key">When this method returns, contains a SecurityKey that contains the key that is referenced in the specified key identifier clause. This parameter is passed uninitialized.</param>
        /// <returns>true when a key can be retrieved for the specified key identifier clause; otherwise, false. </returns>
        protected override bool TryResolveSecurityKeyCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key )
        {
            return _wrappedResolver.TryResolveSecurityKey( keyIdentifierClause, out key );
        }

        /// <summary>
        /// Attempts to resolve the security token that matches the specified key identifier clause.
        /// </summary>
        /// <param name="keyIdentifierClause">The SecurityKeyIdentifierClause to create a security token for.</param>
        /// <param name="token">When this method returns, contains a SecurityToken that represents the specified key identifier clause. This parameter is passed uninitialized.</param>
        /// <returns>true when a security token can be retrieved for the specified key identifier clause; otherwise, false.</returns>
        protected override bool TryResolveTokenCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token )
        {
            return _wrappedResolver.TryResolveToken( keyIdentifierClause, out token );
        }

        /// <summary>
        /// Attempts to retrieve the security token that matches at least one of the key identifier clauses contained within the specified key identifier.
        /// </summary>
        /// <param name="keyIdentifier">The SecurityKeyIdentifier to create a security token for.</param>
        /// <param name="token">When this method returns, contains a SecurityToken that represents the specified key identifier. This parameter is passed uninitialized.</param>
        /// <returns>true when a security token can be retrieved for the specified key identifier; otherwise, false.</returns>
        protected override bool TryResolveTokenCore( SecurityKeyIdentifier keyIdentifier, out SecurityToken token )
        {
            return _wrappedResolver.TryResolveToken( keyIdentifier, out token );
        }
    }
}
