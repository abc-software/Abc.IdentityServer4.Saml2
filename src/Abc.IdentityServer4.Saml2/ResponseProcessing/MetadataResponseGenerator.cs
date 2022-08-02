// ----------------------------------------------------------------------------
// <copyright file="MetadataResponseGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Sustainsys.Saml2.Metadata;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    /// <summary>
    /// The SAML2 metadata response generator implementation.
    /// </summary>
    /// <seealso cref="Abc.IdentityServer4.Saml2.ResponseProcessing.IMetadataResponseGenerator" />
    public class MetadataResponseGenerator : IMetadataResponseGenerator
    {
        private readonly IdentityServerOptions _options;
        private readonly IResourceStore _resources;
        private readonly Services.IClaimsService _claims;
        private readonly IKeyMaterialService _keys;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly Saml2SPOptions _spOptions;

        /// <summary>
        /// Initializes a new instance of the <see cref="MetadataResponseGenerator"/> class.
        /// </summary>
        /// <param name="keys">The keys.</param>
        /// <param name="contextAccessor">The context accessor.</param>
        /// <param name="options">The options.</param>
        public MetadataResponseGenerator(
            IdentityServerOptions options,
            IResourceStore resources,
            Services.IClaimsService claimsService,
            IKeyMaterialService keys, 
            IHttpContextAccessor contextAccessor, 
            Saml2SPOptions spOptions)
        {
            _options = options;
            _resources = resources;
            _claims = claimsService;
            _keys = keys;
            _contextAccessor = contextAccessor;
            _spOptions = spOptions;
        }

        /// <inheritdoc/>
        public virtual async Task<MetadataBase> GenerateMetadata()
        {
            var credentials = await _keys.GetX509SigningCredentialsAsync();
            var signingKey = credentials.Key as X509SecurityKey;

            var issuer = _contextAccessor.HttpContext.GetIdentityServerIssuerUri();
            var baseUrl = _contextAccessor.HttpContext.GetIdentityServerBaseUrl();
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            var entityDescriptor = new EntityDescriptor(new EntityId(issuer));
            var descriptor = new IdpSsoDescriptor();

            if (_spOptions.WantAuthenticationRequestsSigned)
            {
                descriptor.WantAuthnRequestsSigned = true;
            }

            if (_options.Discovery.ShowKeySet)
            {
                var x509Data = new Sustainsys.Saml2.Metadata.X509Data();
                x509Data.Certificates.Add(signingKey.Certificate);

                var keyInfo = new DSigKeyInfo();
                keyInfo.Data.Add(x509Data);

                var keyDescriptor = new KeyDescriptor()
                {
                    //KeyInfo = new KeyInfo(cert),
                    KeyInfo = keyInfo,
                    Use = KeyType.Signing,
                };

                descriptor.Keys.Add(keyDescriptor);
            }

            descriptor.NameIdentifierFormats.Add(new NameIDFormat() { Uri = Saml2Constants.NameIdentifierFormats.Unspecified });
            descriptor.NameIdentifierFormats.Add(new NameIDFormat() { Uri = Saml2Constants.NameIdentifierFormats.Transient });
            descriptor.NameIdentifierFormats.Add(new NameIDFormat() { Uri = Saml2Constants.NameIdentifierFormats.Persistent });

            descriptor.ProtocolsSupported.Add(new Uri(Saml2Constants.Namespaces.Protocol));

            if (_options.Discovery.ShowEndpoints)
            {
                descriptor.SingleSignOnServices.Add(new SingleSignOnService() { Binding = Saml2Constants.ProtocolBindings.HttpRedirect, Location = new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash()) });
                descriptor.SingleSignOnServices.Add(new SingleSignOnService() { Binding = Saml2Constants.ProtocolBindings.HttpPost, Location = new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash()) });
                descriptor.SingleLogoutServices.Add(new SingleLogoutService() { Binding = Saml2Constants.ProtocolBindings.HttpRedirect, Location = new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash()) });
                descriptor.SingleLogoutServices.Add(new SingleLogoutService() { Binding = Saml2Constants.ProtocolBindings.HttpPost, Location = new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash()) });
                descriptor.ArtifactResolutionServices.Add(0, new ArtifactResolutionService() { Binding = Saml2Constants.ProtocolBindings.Soap, Location = new Uri(baseUrl + Constants.ProtocolRoutePaths.ArtefactResolutionService.EnsureLeadingSlash()) });
            }

            if (_options.Discovery.ShowClaims)
            {
                var resources = await _resources.GetAllEnabledResourcesAsync();

                // exclude standard OIDC identity resources
                var oidcResources = new[] { IdentityServerConstants.StandardScopes.OpenId, IdentityServerConstants.StandardScopes.Profile };
                var claims = resources
                    .IdentityResources.Where(x => x.ShowInDiscoveryDocument && !oidcResources.Contains(x.Name))
                    .SelectMany(x => x.UserClaims)
                    .Distinct()
                    .Select(c => new Claim(c, string.Empty));

                var mappedClaims = _claims.MapClaims(_spOptions.DefaultClaimMapping, claims);
                foreach (var item in mappedClaims)
                {
                    descriptor.SupportedAttributes.Add(new Microsoft.IdentityModel.Tokens.Saml2.Saml2Attribute(item.Type) { NameFormat = Saml2Constants.AttributeNameFormats.Uri });
                }
            }

            /* TODO: convert JWT algorithms names to XMLSignature
            var signingCredentialsAll = await _keys.GetAllX509SigningCredentialsAsync();
            if (signingCredentialsAll.Any())
            {
                var signingAlgorithms = signingCredentialsAll.Select(c => new { c.Algorithm, c.Key.KeySize }).Distinct();
                var digestAlgorithms = signingCredentialsAll.Select(c => c.Digest).Distinct();

                var doc = new XmlDocument();
                foreach (var signingAlgorithm in signingAlgorithms)
                {
                    var el = doc.CreateElement("SigningMethod", "urn:oasis:names:tc:SAML:metadata:algsupport");
                    el.SetAttribute("Algorithm", signingAlgorithm.Algorithm);
                    el.SetAttribute("MinKeySize", signingAlgorithm.KeySize.ToString());
                    entityDescriptor.Extensions.Add(el);
                }

                foreach (var digestAlgorithm in digestAlgorithms)
                {
                    var el = doc.CreateElement("DigestMethod", "urn:oasis:names:tc:SAML:metadata:algsupport");
                    el.SetAttribute("Algorithm", digestAlgorithm);
                    entityDescriptor.Extensions.Add(el);
                }
            }
            */

            entityDescriptor.RoleDescriptors.Add(descriptor);
            entityDescriptor.SigningCredentials = signingCredentials;
            return entityDescriptor;
        }
    }
}