// ----------------------------------------------------------------------------
// <copyright file="MetadataResult.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Hosting;
using Microsoft.AspNetCore.Http;
using Sustainsys.Saml2.Metadata;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results
{
    public class MetadataResult : IEndpointResult
    {
        private readonly MetadataBase _metadata;

        public MetadataResult(MetadataBase metadata)
        {
            _metadata = metadata ?? throw new System.ArgumentNullException(nameof(metadata));
        }

        public Task ExecuteAsync(HttpContext context)
        {
            var ser = new MetadataSerializer();
            using var ms = new MemoryStream();
            ser.WriteMetadata(ms, _metadata);
            context.Response.ContentType = "application/samlmetadata+xml"; // "application/xml"
            var metaAsString = Encoding.UTF8.GetString(ms.ToArray());
            return context.Response.WriteAsync(metaAsString);
        }
    }
}