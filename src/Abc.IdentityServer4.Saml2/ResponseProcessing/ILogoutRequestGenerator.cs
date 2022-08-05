// ----------------------------------------------------------------------------
// <copyright file="ILogoutRequestGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    internal interface ILogoutRequestGenerator
    {
        Task<HttpSaml2Message2> GenerateRequestAsync(Saml2RequestValidationResult validationResult);
    }
}