using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin;
using Sustainsys.Saml2.WebSso;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Hosting;
using System.Xml.Linq;

namespace Mvc5App48.Owin4.Saml2 {
    public partial class Startup {
        private static string realm = ConfigurationManager.AppSettings["ida:Wtrealm"];
        private static string adfsMetadata = ConfigurationManager.AppSettings["ida:ADFSMetadata"];

        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app) {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions() {
                CookiePath = HostingEnvironment.ApplicationVirtualPath,
                CookieSameSite = Microsoft.Owin.SameSiteMode.None, 
            });

            app.UseSaml2Authentication(CreateSaml2Options());
        }

        private static Saml2AuthenticationOptions CreateSaml2Options() {
            var spOptions = new SPOptions {
                EntityId = new EntityId(realm),
                AuthenticateRequestSigningBehavior = SigningBehavior.IfIdpWantAuthnRequestsSigned,
                ReturnUrl = new Uri(System.Web.VirtualPathUtility.ToAbsolute("~/Home"), UriKind.Relative),
            };

            spOptions.ServiceCertificates.Add(new X509Certificate2(
                AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "/App_Data/saml2.sample.pfx", "abc"));

            var saml2Options = new Saml2AuthenticationOptions(false) {
                SPOptions = spOptions
            };

            var ed = MetadataLoader.LoadIdp(adfsMetadata, false);

            var idp = new IdentityProvider(ed.EntityId, spOptions) {
                AllowUnsolicitedAuthnResponse = true,
            };
            
            idp.ReadMetadata(ed);
            saml2Options.IdentityProviders.Add(idp);

            return saml2Options;
        }
    }
}