// ----------------------------------------------------------------------------
// <copyright file="SoapConstants.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using System.Diagnostics.CodeAnalysis;

namespace Abc.IdentityServer4.Saml2
{
    [ExcludeFromCodeCoverage]
    internal sealed class SoapConstants
    {
        private SoapConstants()
        {
        }

        public sealed class Namespaces
        {
            public const string Soap12 = "http://www.w3.org/2003/05/soap-envelope";
            public const string Soap11 = "http://schemas.xmlsoap.org/soap/envelope/";
            public const string None = "http://schemas.microsoft.com/ws/2005/05/envelope/none";

            private Namespaces()
            {
            }
        }

        public sealed class ElementNames
        {
            public const string Fault = "Fault";
            public const string Envelope = "Envelope";
            public const string Body = "Body";
            public const string Header = "Header";

            private ElementNames()
            {
            }
        }
    }
}