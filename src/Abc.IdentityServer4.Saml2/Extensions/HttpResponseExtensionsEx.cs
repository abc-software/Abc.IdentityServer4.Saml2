// ----------------------------------------------------------------------------
// <copyright file="HttpResponseExtensionsEx.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Configuration;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Http;

namespace IdentityServer4.Extensions
{
    internal static class HttpResponseExtensionsEx
    {
        public static void AddSignInFormPostCspHeaders(this HttpResponse response, CspOptions options, string origin, string scriptHash, string styleHash)
        {
            var csp1part = options.Level == CspLevel.One ? "'unsafe-inline' " : string.Empty;
            var scriptHashPart = scriptHash.IsPresent() ? $"'{scriptHash}' " : string.Empty;
            var styleHashPart = styleHash.IsPresent() ? $"'{styleHash}' " : string.Empty;
            var cspHeader = $"default-src 'none'; img-src data:; frame-ancestors {origin}; style-src {csp1part}{styleHashPart}; script-src {csp1part}{scriptHashPart}";

            HttpResponseExtensions.AddCspHeaders(response.Headers, options, cspHeader);
        }

        public static void AddFormPostCspHeaders(this HttpResponse response, CspOptions options, string hash, string nonce, string frameSources)
        {
            var csp1part = options.Level == CspLevel.One ? "'unsafe-inline' " : string.Empty;
            var hashPart = hash.IsPresent() ? $"'{hash}'" : string.Empty;
            var noncePart = nonce.IsPresent() ? $"'nonce-{nonce}' " : string.Empty;

            var cspHeader = $"default-src 'none'; style-src {csp1part}{hashPart}; script-src {csp1part}{noncePart}";

            if (!string.IsNullOrEmpty(frameSources))
            {
                cspHeader += $"https://code.jquery.com/jquery-3.5.1.slim.min.js; frame-src {frameSources}";
            }

            HttpResponseExtensions.AddCspHeaders(response.Headers, options, cspHeader);
        }
    }
}