// ----------------------------------------------------------------------------
// <copyright file="SignInResponseGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    internal class SignInResponseGenerator : ISignInResponseGenerator
    {
        private readonly ILogger _logger;
        private readonly Saml2SPOptions _options;
        private readonly IResourceStore _resources;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IKeyMaterialService _keys;
        private readonly Services.IClaimsService _claimsService;
        private readonly ISystemClock _clock;
        private readonly Stores.IArtifactStore _artifactStore;

        public SignInResponseGenerator(
            ILogger<SignInResponseGenerator> logger,
            Saml2SPOptions options,
            IResourceStore resources,
            IHttpContextAccessor contextAccessor,
            IKeyMaterialService keys,
            Services.IClaimsService claimsService,
            ISystemClock clock,
            Stores.IArtifactStore artifactStore = null)
        {
            _logger = logger;
            _options = options;
            _resources = resources;
            _contextAccessor = contextAccessor;
            _keys = keys;
            _claimsService = claimsService;
            _clock = clock;
            _artifactStore = artifactStore;
        }

        public async Task<HttpSaml2Message2> GenerateResponseAsync(Saml2RequestValidationResult validationResult)
        {
            _logger.LogDebug("Creating SAML2 signin response");

            var outgoingSubject = await CreateSubjectAsync(validationResult);

            return await CreateResponseAsync(validationResult.ValidatedRequest, outgoingSubject);
        }

        protected virtual async Task<ClaimsIdentity> CreateSubjectAsync(Saml2RequestValidationResult result)
        {
            var validatedRequest = result.ValidatedRequest;
            var relyingParty = validatedRequest.RelyingParty;
            var claimsMapping =
                relyingParty?.ClaimMapping != null && relyingParty.ClaimMapping.Any()
                ? relyingParty.ClaimMapping
                : _options.DefaultClaimMapping;

            var requestedClaimTypes = await GetRequestedClaimTypesAsync(validatedRequest.ValidatedResources.ParsedScopes.Select(x => x.ParsedName));

            // TODO:
            // requested claims
            //foreach (var claimType in validatedRequest.Saml2RequestMessage.Saml2Request.Select(a => a.Definition))
            //{
            //    var pair = claimsMapping.FirstOrDefault(x => x.Value == claimType);
            //    if (/*claimMapping.ContainsKey(claimType)*/ pair.Key != null)
            //    {
            //        var jwtClaimType = pair.Key; //claimMapping[claimType];
            //        requestedClaims.Add(jwtClaimType);
            //    }
            //    else
            //    {
            //        requestedClaims.Add(claimType);
            //    }
            //}

            var issuedClaims = await _claimsService.GetClaimsAsync(validatedRequest, requestedClaimTypes);

            var outboundClaims = new List<Claim>();
            outboundClaims.AddRange(_claimsService.MapClaims(claimsMapping, issuedClaims));

            if (!outboundClaims.Exists(x => x.Type == ClaimTypes.NameIdentifier))
            {
                var nameid = new Claim(ClaimTypes.NameIdentifier, validatedRequest.Subject.GetSubjectId());
                nameid.Properties[Microsoft.IdentityModel.Tokens.Saml.ClaimProperties.SamlNameIdentifierFormat] =
                    validatedRequest.RelyingParty?.NameIdentifierFormat ?? _options.DefaultNameIdentifierFormat;
                outboundClaims.Add(nameid);
            }

            // The AuthnStatement statement generated from the following 2
            // claims is mandatory for some service providers (i.e. Shibboleth-Sp). 
            // The value of the AuthenticationMethod claim must be one of the constants in
            // System.IdentityModel.Tokens.AuthenticationMethods.
            // Password is the only one that can be directly matched, everything
            // else defaults to Unspecified.
            if (!outboundClaims.Exists(x => x.Type == ClaimTypes.AuthenticationMethod))
            {
                var authenticationMethod = validatedRequest.Subject.GetAuthenticationMethod() == OidcConstants.AuthenticationMethods.Password
                    ? SamlConstants.AuthenticationMethods.PasswordString
                    : SamlConstants.AuthenticationMethods.UnspecifiedString;
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, authenticationMethod));
            }

            // authentication instant claim is required
            if (!outboundClaims.Exists(x => x.Type == ClaimTypes.AuthenticationInstant))
            {
                outboundClaims.Add(new Claim(ClaimTypes.AuthenticationInstant, validatedRequest.Subject.GetAuthenticationTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"), ClaimValueTypes.DateTime));
            }

            return new ClaimsIdentity(outboundClaims, "idsrv");
        }

        protected virtual async Task<IList<string>> GetRequestedClaimTypesAsync(IEnumerable<string> scopes)
        {
            var requestedClaimTypes = new List<string>();

            var resources = await _resources.FindEnabledIdentityResourcesByScopeAsync(scopes);
            foreach (var resource in resources)
            {
                foreach (var claim in resource.UserClaims)
                {
                    requestedClaimTypes.Add(claim);
                }
            }

            return requestedClaimTypes;
        }

        protected SecurityToken CreateToken(SecurityTokenDescriptor descriptor)
        {
            var handler = _options.SecurityTokenHandler;

            if (descriptor.Subject.HasClaim(c => c.Type == ClaimTypes.AuthenticationMethod) &&
                descriptor.Subject.HasClaim(c => c.Type == ClaimTypes.AuthenticationInstant))
            {
                // if we have authentication information set via claims
                // create AuthenticationInformation from the corresponding namespaces
                // and pass it to the right handler
                var authMethod = descriptor.Subject.Claims.Single(x => x.Type == ClaimTypes.AuthenticationMethod).Value;
                var authTime = descriptor.Subject.Claims.Single(x => x.Type == ClaimTypes.AuthenticationInstant).Value;

                var auth = new Microsoft.IdentityModel.Tokens.Saml2.AuthenticationInformation(new Uri(authMethod), DateTime.Parse(authTime));
                return handler.CreateToken(descriptor, auth);
            }

            return handler.CreateToken(descriptor);
        }

        private async Task<HttpSaml2Message2> CreateResponseAsync(ValidatedSaml2Request validatedRequest, ClaimsIdentity outgoingSubject)
        {
            var credentials = await _keys.GetX509SigningCredentialsAsync();
            var issuer = _contextAccessor.HttpContext.GetIdentityServerIssuerUri();
            var issueInstant = _clock.UtcNow.UtcDateTime;

            var signingCredentials = new SigningCredentials(
                credentials.Key,
                validatedRequest.RelyingParty?.SignatureAlgorithm ?? _options.DefaultSignatureAlgorithm,
                validatedRequest.RelyingParty?.DigestAlgorithm ?? _options.DefaultDigestAlgorithm);

            var descriptor = new SecurityTokenDescriptor
            {
                Audience = validatedRequest.Client.ClientId,
                IssuedAt = issueInstant,
                NotBefore = issueInstant,
                Expires = issueInstant.AddSeconds(validatedRequest.Client.AccessTokenLifetime),
                Subject = outgoingSubject,
                Issuer = issuer,
            };

            var wantAssertionSigned = validatedRequest.RelyingParty?.SignAssertion.HasValue == true
                ? validatedRequest.RelyingParty.SignAssertion.Value
                : _options.SignAssertion;
            if (wantAssertionSigned)
            {
                descriptor.SigningCredentials = signingCredentials;
            }

            if (validatedRequest.RelyingParty?.EncryptionCertificate != null)
            {
                descriptor.EncryptingCredentials = new X509EncryptingCredentials(
                    validatedRequest.RelyingParty.EncryptionCertificate,
                    validatedRequest.RelyingParty.KeyWrapAlgorithm ?? _options.DefaultKeyWrapAlgorithm,
                    validatedRequest.RelyingParty.EncryptionAlgorithm ?? _options.DefaultEncryptionAlgorithm);
            }

            var token = CreateToken(descriptor) as Saml2SecurityToken;
            Debug.Assert(token != null, "Security token MUST be present SAML2 token");

            var assertion = token.Assertion;
            Debug.Assert(assertion != null, "SAML2 assertion MUST be present in SAML2 token");
            Debug.Assert(assertion.Subject != null, "Subject must be present in SAML2 assertion");
            Debug.Assert(assertion.Subject.SubjectConfirmations.Count == 1, "SubjectConfirmation MUST be present in SAML2 assertion subject");
            Debug.Assert(assertion.Subject.SubjectConfirmations.First().Method == Microsoft.IdentityModel.Tokens.Saml2.Saml2Constants.ConfirmationMethods.Bearer, "SubjectConfirmation MUST be Bearer token");

            var samlRequest = validatedRequest.Saml2RequestMessage?.Saml2Request as Saml2AuthenticationRequest;
            Debug.Assert(samlRequest != null, "Request MUST be Saml2AuthenticationRequest");

            var subjectConfirmationData = new Saml2SubjectConfirmationData()
            {
                Recipient = new Uri(validatedRequest.ReplyUrl),
                InResponseTo = samlRequest.Id,
                Address = _contextAccessor.HttpContext.GetClientIpAddress(),
                NotOnOrAfter = issueInstant + _options.MessageLifetime,
            };

            var includeSubjectConfirmationDataNotBefore = validatedRequest.RelyingParty?.IncludeSubjectConfirmationDataNotBefore.HasValue == true
                ? validatedRequest.RelyingParty.IncludeSubjectConfirmationDataNotBefore.Value
                : _options.IncludeSubjectConfirmationDataNotBefore;
            if (includeSubjectConfirmationDataNotBefore) 
            {
                subjectConfirmationData.NotBefore = includeSubjectConfirmationDataNotBefore ? issueInstant : null;
            }

            assertion.Subject.SubjectConfirmations.First().SubjectConfirmationData = subjectConfirmationData;

            if (assertion.Subject.NameId != null)
            {
                var authenticationStatement = assertion.Statements.OfType<Saml2AuthenticationStatement>().FirstOrDefault();
                if (authenticationStatement != null)
                {
                    authenticationStatement.SessionIndex = assertion.Id.Value;

                    validatedRequest.SessionParticipant = new Saml2SessionParticipant(
                        descriptor.Audience,
                        assertion.Subject.NameId.Format,
                        assertion.Subject.NameId.NameQualifier,
                        assertion.Subject.NameId.SPNameQualifier,
                        assertion.Subject.NameId.SPProvidedId,
                        authenticationStatement.SessionIndex);
                }
            }

            var singleSignOnService = validatedRequest.RelyingParty?.SingleSignOnServices.FirstOrDefault();
            var destination = singleSignOnService?.Location ?? validatedRequest.ReplyUrl;

            var samlResponse = new Saml2Response(new Saml2Status(Saml2StatusCode.Success))
            {
                IssueInstant = issueInstant,
                InResponseTo = samlRequest.Id,
                Issuer = new Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier(issuer),
                Destination = new Uri(destination),
                SigningCredentials = signingCredentials,
            };

            samlResponse.Assertions.Add(new IdentityModel.Protocols.SecurityTokenElement(token));

            // Build Response message
            if (string.Equals(singleSignOnService?.Binding, Abc.IdentityModel.Protocols.Saml2.Saml2Constants.ProtocolBindings.HttpArtifactString))
            {
                // Save IssuedToken to ArtifactStorage
                if (_artifactStore == null)
                {
                    throw new InvalidOperationException("Artifact storage not set.");
                }

                var artifact = new SamlArtifact4(0, issuer).ToString();
                await _artifactStore.StoreAsync(artifact, validatedRequest.Client.ClientId, samlResponse, issueInstant, issueInstant + _options.MessageLifetime);

                return new HttpSaml2ArtifactMessage2(samlResponse.Destination, artifact)
                {
                    RelayState = validatedRequest.Saml2RequestMessage.RelayState,
                };
            }

            return new HttpSaml2ResponseMessage2(samlResponse.Destination, samlResponse, IdentityModel.Http.HttpDeliveryMethods.PostRequest)
            {
                RelayState = validatedRequest.Saml2RequestMessage.RelayState,
            };
        }
    }
}