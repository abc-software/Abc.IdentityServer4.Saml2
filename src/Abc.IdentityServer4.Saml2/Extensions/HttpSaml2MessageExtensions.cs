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
using Abc.IdentityServer4.Saml2;

namespace Abc.IdentityModel.Protocols.Saml2
{
    public static class HttpSaml2MessageExtensions
    {
        internal static IDictionary<string, string[]> ToDictionary(this HttpSaml2Message2 message)
        {
            if (message is null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return new HttpSaml2MessageSerializer(null)
                .EncodeToDictionary(message)
                .ToDictionary(k => k.Key, e => new string[] { e.Value });
        }

        internal static HttpSaml2Message2 ToSaml2Message(this IDictionary<string, string[]> data)
        {
            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
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

        private static IList<Uri> GetRequestedAuthenticationContextClassReferences(this Saml2Request request)
        {
            if (request is Saml2AuthenticationRequest saml2AuthnRequest 
                && saml2AuthnRequest.RequestedAuthenticationContext?.ReferenceType == Saml2AuthenticationContextReferenceType.Class)
            {
                return saml2AuthnRequest.RequestedAuthenticationContext.References;
            }

            return new Collection<Uri>();
        }

        internal static string GetPrefixedAcrValue(this Saml2Request request, string prefix)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var value = referenceClasses.FirstOrDefault(x => x.Scheme == prefix);
            if (value != null)
            {
                return value.LocalPath;
            }

            return null;
        }

        internal static string GetIdP(this Saml2Request request)
        {
            return request.GetPrefixedAcrValue(Constants.KnownAcrShemes.HomeRealm);
        }

        internal static string GetTenant(this Saml2Request request)
        {
            return request.GetPrefixedAcrValue(Constants.KnownAcrShemes.Tenant);
        }

        internal static IEnumerable<string> GetAcrValues(this Saml2Request request)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            return referenceClasses
                .Where(acr => !Constants.KnownAcrShemes.All.Any(well_known => acr.Scheme == well_known))
                .Select(acr => acr.OriginalString)
                .Distinct()
                .ToArray();
        }

        internal static void RemovePrefixedAcrValue(this Saml2Request request, string prefix)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var itemsToRemove = referenceClasses.Where(x => x.Scheme == prefix);
            foreach (var item in itemsToRemove)
            {
                referenceClasses.Remove(item);
            }
        }

        internal static void RemoveAcrValue(this Saml2Request request, Uri value)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var itemsToRemove = referenceClasses.Where(x => x == value);
            foreach (var item in itemsToRemove)
            {
                referenceClasses.Remove(item);
            }
        }

        internal static void RemoveIdP(this Saml2Request request)
        {
            request.RemovePrefixedAcrValue(Constants.KnownAcrShemes.HomeRealm);
        }
    }
}