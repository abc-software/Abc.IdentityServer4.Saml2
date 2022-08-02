// ----------------------------------------------------------------------------
// <copyright file="ISignInInteractionResponseGenerator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Models;
using IdentityServer4.ResponseHandling;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    /// <summary>
    /// Interface for determining if user must login or consent when making requests to the SAML2 single sign in endpoint.
    /// </summary>
    public interface ISignInInteractionResponseGenerator
    {
        /// <summary>
        /// Processes the interaction logic.
        /// </summary>
        /// <param name="request">The request.</param>
        /// <param name="consent">The consent.</param>
        /// <returns>The interaction response.</returns>
        Task<InteractionResponse> ProcessInteractionAsync(ValidatedSaml2Request request, ConsentResponse consent = null);
    }
}