// ----------------------------------------------------------------------------
// <copyright file="KeyMaterialServiceExtensions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Extensions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer4.Services
{
    internal static class KeyMaterialServiceExtensions
    {
        public static async Task<IEnumerable<SigningCredentials>> GetAllX509SigningCredentialsAsync(this IKeyMaterialService keyMaterialService)
        {
            return (await keyMaterialService.GetAllSigningCredentialsAsync()).Where(c => c.Key is X509SecurityKey);
        }

        public static async Task<SigningCredentials> GetX509SigningCredentialsAsync(this IKeyMaterialService keyMaterialService, IEnumerable<string> allowedAlgorithms = null)
        {
            var credentials = await GetAllX509SigningCredentialsAsync(keyMaterialService);
            if (!credentials.Any())
            {
                throw new InvalidOperationException($"No X509 signing credential registered.");
            }

            if (IEnumerableExtensions.IsNullOrEmpty(allowedAlgorithms))
            {
                return credentials.First();
            }

            var credential = credentials.FirstOrDefault(c => allowedAlgorithms.Contains(c.Algorithm));
            if (credential is null)
            {
                throw new InvalidOperationException($"No X509 signing credential for algorithms ({allowedAlgorithms.ToSpaceSeparatedString()}) registered.");
            }

            return credential;
        }
    }
}