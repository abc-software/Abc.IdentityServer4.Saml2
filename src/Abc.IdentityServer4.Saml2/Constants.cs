// ----------------------------------------------------------------------------
// <copyright file="Constants.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

namespace Abc.IdentityServer4.Saml2
{
    internal static class Constants
    {
        /*
        public static class SamlNameIdentifierFormats
        {
            public const string EmailAddressString = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            public const string EncryptedString = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted";
            public const string EntityString = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
            public const string KerberosString = "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
            public const string PersistentString = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
            public const string TransientString = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
            public const string UnspecifiedString = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
            public const string WindowsDomainQualifiedNameString = "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
            public const string X509SubjectNameString = "urn:oasis:names:tc:SAML:1.1:nameid-format: X509SubjectName";
        }
        */

        internal static class BindingTypes
        {
            public const string RedirectString = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
            public const string ArtifactString = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
            public const string PostString = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
        }

        internal static class EndpointNames
        {
            public const string SingleSignOn = "saml2sso";
            public const string SingleSignOnCallback = "saml2callback";
            public const string ArtefactResolutionService = "saml2ars";
            public const string SingleLogoutService = "saml2slo";
            public const string SingleLogoutServiceCallback = "saml2slocallback";
            public const string Metadata = "metadata";
        }

        internal static class ProtocolRoutePaths
        {
            public const string Saml2Prefix = "saml2";
            public const string SingleSignOn = Saml2Prefix;
            public const string SigleSignOnCallback = SingleSignOn + "/callback";
            public const string Metadata = Saml2Prefix + "/metadata";
            public const string ArtefactResolutionService = Saml2Prefix + "/ars";
            public const string SingleLogoutService = Saml2Prefix + "/slo";
            public const string SingleLogoutServiceCallback = SingleLogoutService + "/callback";
        }

        internal static class DefaultRoutePathParams
        {
            public const string MessageStoreIdParameterName = "authzId";
            public const string EndSessionCallback = "endSessionId";
            public const string RequestIdParameterName = "requestId";
        }

        internal static class KnownAcrShemes
        {
            public const string HomeRealm = "idp";

            public const string Tenant = "tenant";

            public static readonly string[] All = new string[] { HomeRealm, Tenant };
        }
    }
}