// ----------------------------------------------------------------------------
// <copyright file="Saml2ArtifactResolutionEndpoint.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Stores;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using IdentityServer4.Hosting;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2ArtifactResolutionEndpoint : IEndpointHandler
    {
        private readonly Saml2ProtocolSerializer _samlProtocolSerializer = new Saml2ProtocolSerializer();
        private readonly Stores.IArtifactStore _artifactStore;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IKeyMaterialService _keys;
        private readonly ILogger _logger;

        public Saml2ArtifactResolutionEndpoint(
            IArtifactStore artifactStore, 
            IHttpContextAccessor contextAccessor, 
            IKeyMaterialService keys,
            ILogger<Saml2ArtifactResolutionEndpoint> logger)
        {
            _artifactStore = artifactStore;
            _contextAccessor = contextAccessor;
            _keys = keys;
            _logger = logger;
        }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            var syncIOFeature = context.Features.Get<IHttpBodyControlFeature>();
            if (syncIOFeature != null) 
            {
                syncIOFeature.AllowSynchronousIO = true;
            }

            var result = ValidateRequest(context.Request);
            if (result != null)
            {
                return result;
            }

            var request = ReadProtocolMessage(context.Request) as Saml2ArtifactResolve;

            var response = await ProcessSamlRequestAsync(request);

            return new BodyWriter(_samlProtocolSerializer, response);
        }

        /// <summary>
        /// Processes the SAML2 protocol request.
        /// </summary>
        /// <param name="artifactRequest">The SAML2 ArtifactResolve request.</param>
        /// <returns>The SAML2 protocol response.</returns>
        public async Task<Saml2ArtifactResponse> ProcessSamlRequestAsync(Saml2ArtifactResolve artifactRequest)
        {
            if (artifactRequest == null)
            {
                throw new ArgumentNullException(nameof(artifactRequest));
            }

            // Request Issuer MUST be set
            if (artifactRequest.Issuer == null || string.IsNullOrEmpty(artifactRequest.Issuer.Value))
            {
                throw new SamlArtifactResolutionServiceException("Received artifact resolution request without issuer");
            }

            // Request MUST be signed
            if (artifactRequest.SigningCredentials == null) {
                // Warning("SAML artifact resolution request without signature received with request issuer: {0}", new object[] { request.Issuer.Value });
                // throw new SamlArtifactResolutionServiceNoSignatureException(request.Issuer.Value);
                // TODO: throw new SamlArtifactResolutionServiceException("ArtifactResolve message must be signed. ArtifactResolve issuer: '{0}'."); // TODO:
            }

            var issuer = _contextAccessor.HttpContext.GetIdentityServerIssuerUri();

            var artifactResponse = new Saml2ArtifactResponse(new Saml2Status(Saml2StatusCode.Success))
            {
                Issuer = new Saml2NameIdentifier(issuer),
                InResponseTo = artifactRequest.Id,
            };

            if (!string.IsNullOrEmpty(artifactRequest.Artifact))
            {
                var samlArtifact = SamlArtifact.LoadSamlArtifactFromString(artifactRequest.Artifact);

                // Validate artifact
                if (!samlArtifact.VerifyArtifact(issuer))
                {
                    throw new SamlArtifactResolutionServiceException($"SAML artifact resolution request required Artifact with SourceId that does not correspond to server issuer.");
                }

                // Validate ServiceEndPoint
                if (samlArtifact is SamlArtifact4 samlArtifact4 && samlArtifact4.EndpointIndex != 0)
                {
                    throw new SamlArtifactResolutionServiceException($"Wrong EndpointIndex in artifact. Obtained: '{samlArtifact4.EndpointIndex}'. Expected: '0'");
                }

                // Get SecurityToken from Artifact Store
                var response = await _artifactStore.GetAsync(artifactRequest.Artifact);
                if (response != null)
                {
                    artifactResponse.Response = response;

                    // [SAMLBindings, "Forged SAML Artifact"]
                    await _artifactStore.RemoveAsync(artifactRequest.Artifact);
                }
            }

            // Sign Response with SHA1 Asymmetric
            var credentials = await _keys.GetX509SigningCredentialsAsync();
            artifactResponse.SigningCredentials = new SigningCredentials(credentials.Key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

            return artifactResponse;
        }

        protected Saml2Message ReadProtocolMessage(HttpRequest request)
        {
            using var reader = XmlReader.Create(request.Body);
            reader.MoveToContent();

            // <Envelope>
            reader.ReadStartElement(SoapConstants.ElementNames.Envelope, SoapConstants.Namespaces.Soap11);

            // <Header>
            if (reader.IsStartElement(SoapConstants.ElementNames.Header, SoapConstants.Namespaces.Soap11))
            {
                reader.Skip();
            }

            // <Body>
            reader.ReadStartElement(SoapConstants.ElementNames.Body, SoapConstants.Namespaces.Soap11);

            var message = _samlProtocolSerializer.ReadSamlMessage(reader);

            // </Body>
            reader.ReadEndElement();

            // </Envelope>
            reader.ReadEndElement();

            return message;
        }

        protected IEndpointResult ValidateRequest(HttpRequest request)
        {
            if (!HttpMethods.IsPost(request.Method))
            {
                _logger.LogWarning("SAML2 artifact endpoint only supports POST requests");
                return new StatusCodeResult(System.Net.HttpStatusCode.MethodNotAllowed);
            }

            // Content-Type should be text/xml; charset="utf-8"
            var contentType = new ContentType(request.ContentType);
            if (contentType.MediaType != "text/xml" && contentType.CharSet != "utf-8")
            {
                _logger.LogWarning("SAML2 artifact endpoint only supports 'text/xml' media type");
                return new StatusCodeResult(System.Net.HttpStatusCode.UnsupportedMediaType);
            }

            // SOAPAction should be http://www.oasis-open.org/committees/security
            var action = request.Headers["SOAPAction"].ToString();
            if (action != "http://www.oasis-open.org/committees/security")
            {
                _logger.LogWarning("SAML2 artifact endpoint must be with valid SOAPAction header");
                return new StatusCodeResult(System.Net.HttpStatusCode.BadRequest);
            }

            // Body is empty

            return null;
        }

        private class BodyWriter : IEndpointResult
        {
            private readonly Saml2Message _samlMessage;
            private readonly Saml2ProtocolSerializer _samlProtocolSerializer;

            /// <summary>
            /// Initializes a new instance of the <see cref="BodyWriter"/> class.
            /// </summary>
            /// <param name="samlProtocolSerializer">The SAML2 protocol serializer.</param>
            /// <param name="samlMessage">The SAML2 protocol message.</param>
            public BodyWriter(Saml2ProtocolSerializer samlProtocolSerializer, Saml2Message samlMessage)
            {
                _samlMessage = samlMessage ?? throw new ArgumentNullException(nameof(samlMessage));
                _samlProtocolSerializer = samlProtocolSerializer ?? throw new ArgumentNullException(nameof(samlProtocolSerializer));
            }

            public Task ExecuteAsync(HttpContext context)
            {
                // Content-Type should be text/xml; charset="utf-8"
                var contentType = new ContentType() { MediaType = "text/xml", CharSet = "utf-8" };
                context.Response.ContentType = contentType.ToString();

                using (var writer = XmlWriter.Create(context.Response.Body, new XmlWriterSettings() { Encoding = Encoding.UTF8 }))
                {
                    writer.WriteStartElement(SoapConstants.ElementNames.Envelope, SoapConstants.Namespaces.Soap11);
                    writer.WriteStartElement(SoapConstants.ElementNames.Body, SoapConstants.Namespaces.Soap11);

                    _samlProtocolSerializer.WriteSamlMessage(writer, _samlMessage);

                    writer.WriteEndElement();
                    writer.WriteEndElement();
                }

                context.Response.Body.Flush();
                return Task.CompletedTask;
            }
        }
    }

    public class SamlArtifactResolutionServiceException : InvalidOperationException
    {
        public SamlArtifactResolutionServiceException(string message) 
            : base(message)
        {
        }
    }
}