// ----------------------------------------------------------------------------
// <copyright file="HttpMethodsExtension.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Abc.IdentityServer4.Saml2.Extensions
{
    internal static class HttpMethodsExtension
    {
        public static string ToBidningString(this HttpDeliveryMethods deliveryMethods)
        {
            switch (deliveryMethods)
            {
                case HttpDeliveryMethods.PostRequest:
                    return Saml2Constants.ProtocolBindings.HttpPostString;
                case HttpDeliveryMethods.GetRequest:
                    return Saml2Constants.ProtocolBindings.HttpRedirectString;
                default:
                    throw new InvalidCastException();
            }
        }
    }
}
