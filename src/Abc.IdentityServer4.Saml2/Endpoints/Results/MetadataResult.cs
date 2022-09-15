// ----------------------------------------------------------------------------
// <copyright file="MetadataResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Metadata;
using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    public class MetadataResult : IEndpointResult
    {
        private readonly DescriptorBase _metadata;

        public MetadataResult(DescriptorBase metadata)
        {
            _metadata = metadata ?? throw new System.ArgumentNullException(nameof(metadata));
        }

        public Task ExecuteAsync(HttpContext context)
        {
            var ser = new MetadataSerializer();
            using var stream = new MemoryStream();
            using (var writer = XmlWriter.Create(stream))
            {
                ser.WriteMetadata(writer, _metadata);
            }

            context.Response.ContentType = "application/samlmetadata+xml"; // "application/xml"
            var metaAsString = Encoding.UTF8.GetString(stream.ToArray());
            return context.Response.WriteAsync(metaAsString);
        }
    }
}