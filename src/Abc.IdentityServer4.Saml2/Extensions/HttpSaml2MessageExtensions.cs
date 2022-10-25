// ----------------------------------------------------------------------------
// <copyright file="HttpSaml2MessageExtensions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Abc.IdentityModel.Http;

namespace Abc.IdentityModel.Protocols.Saml2
{
    public static class HttpSaml2MessageExtensions
    {
        internal static IDictionary<string, string[]> ToDictionary(this HttpSaml2Message2 message)
        {
            if (message is null)
            {
                return new Dictionary<string, string[]>();
            }

            return new HttpSaml2MessageSerializer(null)
                .EncodeToDictionary(message)
                .ToDictionary(k => k.Key, e => new string[] { e.Value });
        }

        internal static HttpSaml2Message2 ToSaml2Message(this IDictionary<string, string[]> data)
        {
            if (data is null || !data.Any())
            {
                return null;
            }

            return new HttpSaml2MessageSerializer(null)
                .DecodeFromDictionary(data.ToDictionary(k => k.Key, e => e.Value.FirstOrDefault()))
                as HttpSaml2Message2;
        }

        public static IEnumerable<Uri> GetDeclarationReferences(this HttpSaml2RequestMessage2 message)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            if (message.Saml2Request is Saml2AuthenticationRequest saml2AuthnRequest 
                && saml2AuthnRequest.RequestedAuthenticationContext?.ReferenceType == Saml2AuthenticationContextReferenceType.Declaration)
            {
                return saml2AuthnRequest.RequestedAuthenticationContext.References;
            }

            return Enumerable.Empty<Uri>();
        }
    }
}