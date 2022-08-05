// ----------------------------------------------------------------------------
// <copyright file="ISaml2EndSessionRequestValidator.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Collections.Specialized;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public interface ISaml2EndSessionRequestValidator
    {
        /// <summary>
        /// Validates requests from logout page iframe to trigger single signout.
        /// </summary>
        Task<Saml2EndSessionCallbackValidationResult> ValidateCallbackAsync(NameValueCollection parameters);
    }
}