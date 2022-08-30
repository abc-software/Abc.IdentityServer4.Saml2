using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Web;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ServiceProvider {
    public class MySaml2AuthenticationModule : Saml2AuthenticationModule {
        public override void SignIn(string returnUrl, string identityProvider, AuthenticationRequest authenticationRequest) {
            if (identityProvider == null) {
                identityProvider = DiscoverIdentityProvider(returnUrl);
            }

            base.SignIn(returnUrl, identityProvider, authenticationRequest);
        }
    }
}