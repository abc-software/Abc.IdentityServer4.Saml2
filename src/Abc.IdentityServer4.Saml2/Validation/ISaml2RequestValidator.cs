// ----------------------------------------------------------------------------
// <copyright file="ISaml2RequestValidator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public interface ISaml2RequestValidator
    {
        Task<Saml2RequestValidationResult> ValidateAsync(HttpSaml2RequestMessage2 message, ClaimsPrincipal user);
    }
}