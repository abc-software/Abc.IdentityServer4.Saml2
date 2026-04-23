// ----------------------------------------------------------------------------
// <copyright file="MetadataResponseGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Metadata;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer.Extensions;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer.Saml2.ResponseProcessing
{
    /// <summary>
    /// The SAML2 metadata response generator implementation.
    /// </summary>
    /// <seealso cref="Abc.IdentityServer.Saml2.ResponseProcessing.IMetadataResponseGenerator" />
    public class MetadataResponseGenerator : IMetadataResponseGenerator
    {
        private readonly IdentityServerOptions _options;
        private readonly IResourceStore _resources;
        private readonly Services.IClaimsService _claims;
        private readonly IServerUrls _urls;
        private readonly IKeyMaterialService _keys;
        private readonly IIssuerNameService _issuerNameService;
        private readonly Saml2SPOptions _spOptions;

        /// <summary>
        /// Initializes a new instance of the <see cref="MetadataResponseGenerator"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="resources">The resource store.</param>
        /// <param name="claimsService">The claims service.</param>
        /// <param name="issuerNameService">The issuer name service.</param>
        /// <param name="urls">The server urls.</param>
        /// <param name="keys">The keys.</param>
        /// <param name="spOptions">The SAML2 service provider options.</param>
        public MetadataResponseGenerator(
            IdentityServerOptions options,
            IResourceStore resources,
            Services.IClaimsService claimsService,
            IIssuerNameService issuerNameService,
            IServerUrls urls,
            IKeyMaterialService keys, 
            Saml2SPOptions spOptions)
        {
            _options = options;
            _resources = resources;
            _claims = claimsService;
            _issuerNameService = issuerNameService;
            _urls = urls;
            _keys = keys;
            _spOptions = spOptions;
        }

        /// <inheritdoc/>
        public virtual async Task<DescriptorBase> GenerateMetadataAsync()
        {
            var credentials = await _keys.GetX509SigningCredentialsAsync();
            var signingKey = credentials.Key as X509SecurityKey;

            var issuer = await _issuerNameService.GetCurrentAsync();
            var baseUrl = _urls.BaseUrl;
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            var entityDescriptor = new EntityDescriptor(new EntityId(issuer));
            var descriptor = new IdpSsoDescriptor();

            descriptor.WantAuthnRequestsSigned = _spOptions.WantAuthenticationRequestsSigned;

            if (_options.Discovery.ShowKeySet)
            {
                var keyDescriptor = new KeyDescriptor(new KeyInfo(signingKey.Certificate))
                {
                    Use = KeyType.Signing,
                };

                descriptor.KeyDescriptors.Add(keyDescriptor);
            }

            descriptor.NameIdFormats.Add(Saml2Constants.NameIdentifierFormats.Unspecified);
            descriptor.NameIdFormats.Add(Saml2Constants.NameIdentifierFormats.Transient);
            descriptor.NameIdFormats.Add(Saml2Constants.NameIdentifierFormats.Persistent);

            descriptor.ProtocolsSupported.Add(new Uri(Saml2Constants.Namespaces.Protocol));

            if (_options.Discovery.ShowEndpoints)
            {
                descriptor.SingleSignOnServices.Add(new EndpointType(Saml2Constants.ProtocolBindings.HttpRedirect, new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash())));
                descriptor.SingleSignOnServices.Add(new EndpointType(Saml2Constants.ProtocolBindings.HttpPost, new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash())));
                descriptor.SingleLogoutServices.Add(new EndpointType(Saml2Constants.ProtocolBindings.HttpRedirect, new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash())));
                descriptor.SingleLogoutServices.Add(new EndpointType(Saml2Constants.ProtocolBindings.HttpPost, new Uri(baseUrl + Constants.ProtocolRoutePaths.SingleSignOn.EnsureLeadingSlash())));
                descriptor.ArtifactResolutionServices.Add(new IndexedEndpointType(0, Saml2Constants.ProtocolBindings.Soap, new Uri(baseUrl + Constants.ProtocolRoutePaths.ArtefactResolutionService.EnsureLeadingSlash())));
            }

            if (_options.Discovery.ShowClaims)
            {
                var resources = await _resources.GetAllEnabledResourcesAsync();

                // exclude standard OIDC identity resources
                var oidcResources = new[] { Ids.IdentityServerConstants.StandardScopes.OpenId, Ids.IdentityServerConstants.StandardScopes.Profile };
                var claims = resources
                    .IdentityResources.Where(x => x.ShowInDiscoveryDocument && !oidcResources.Contains(x.Name))
                    .SelectMany(x => x.UserClaims)
                    .Distinct()
                    .Select(c => new Claim(c, string.Empty));

                var mappedClaims = _claims.MapClaims(_spOptions.DefaultClaimMapping, claims);
                foreach (var item in mappedClaims)
                {
                    descriptor.Attributes.Add(new Microsoft.IdentityModel.Tokens.Saml2.Saml2Attribute(item.Type) { NameFormat = Saml2Constants.AttributeNameFormats.Uri });
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