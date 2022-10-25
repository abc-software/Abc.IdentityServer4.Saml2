// ----------------------------------------------------------------------------
// <copyright file="Saml2RequestExtensions.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityServer4.Saml2;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace Abc.IdentityModel.Protocols.Saml2
{
    internal static class Saml2RequestExtensions
    {
        internal static string GetPrefixedAcrValue(this Saml2Request request, string prefix)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var value = referenceClasses.FirstOrDefault(x => x.IsAbsoluteUri && x.Scheme == prefix);
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
                .Where(acr => !Constants.KnownAcrShemes.All.Any(well_known => acr.IsAbsoluteUri && acr.Scheme == well_known))
                .Select(acr => acr.OriginalString)
                .Distinct()
                .ToArray();
        }

        internal static void RemovePrefixedAcrValue(this Saml2Request request, string prefix)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var itemsToRemove = referenceClasses.Where(x => x.IsAbsoluteUri && x.Scheme == prefix).ToArray();
            foreach (var item in itemsToRemove)
            {
                referenceClasses.Remove(item);
            }
        }

        internal static void RemoveAcrValue(this Saml2Request request, Uri value)
        {
            var referenceClasses = request.GetRequestedAuthenticationContextClassReferences();
            var itemsToRemove = referenceClasses.Where(x => x == value).ToArray();
            foreach (var item in itemsToRemove)
            {
                referenceClasses.Remove(item);
            }
        }

        internal static void RemoveIdP(this Saml2Request request)
        {
            request.RemovePrefixedAcrValue(Constants.KnownAcrShemes.HomeRealm);
        }

        internal static void RemoveTenant(this Saml2Request request)
        {
            request.RemovePrefixedAcrValue(Constants.KnownAcrShemes.Tenant);
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
    }
}