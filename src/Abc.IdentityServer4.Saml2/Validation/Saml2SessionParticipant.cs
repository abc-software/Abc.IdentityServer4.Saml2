// ----------------------------------------------------------------------------
// <copyright file="Saml2SessionParticipant.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using IdentityServer4.Extensions;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Abc.IdentityServer4.Saml2.Validation
{
    public record Saml2SessionParticipant(
        [NotNull] string ClientId,
        [AllowNull] Uri NameIdentifierFormat,
        [AllowNull] string NameIdentifierNameQualifier,
        [AllowNull] string NameIdentifierSPNameQualifier,
        [AllowNull] string NameIdentifierSPProvided,
        [AllowNull] string SessionIndex)
    {
        private const char Separator = ';';

        public static implicit operator string(Saml2SessionParticipant s2id)
        {
            return s2id?.ToString();
        }

        public static explicit operator Saml2SessionParticipant(string str)
        {
            if (str is null)
            {
                throw new ArgumentNullException(nameof(str));
            }

            var arr = str.Split(Separator, 6);
            if (arr.Length == 1)
            {
                return new Saml2SessionParticipant(
                    arr[0],
                    null,
                    null,
                    null,
                    null,
                    null);
            }

            if (arr.Length != 6)
            {
                throw new FormatException();
            }

            return new Saml2SessionParticipant(
                arr[0],
                arr[1].IsPresent() && Uri.TryCreate(arr[1], UriKind.RelativeOrAbsolute, out var format) ? format : null,
                arr[2].IsPresent() ? arr[2] : null,
                arr[3].IsPresent() ? arr[3] : null,
                arr[4].IsPresent() ? arr[4] : null,
                arr[5].IsPresent() ? arr[5] : null);
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            if (NameIdentifierFormat == null
                && NameIdentifierNameQualifier == null
                && NameIdentifierSPNameQualifier == null
                && NameIdentifierSPProvided == null
                && SessionIndex == null)
            {
                return ClientId;
            }  

            return string.Concat(
                ClientId,
                Separator,
                NameIdentifierFormat,
                Separator,
                NameIdentifierNameQualifier,
                Separator,
                NameIdentifierSPNameQualifier,
                Separator,
                NameIdentifierSPProvided,
                Separator,
                SessionIndex);
        }
    }
}