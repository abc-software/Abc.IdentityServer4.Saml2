//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------

using System.Configuration;
using System.Net;
using System.Web;

using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Web;

using WebErrorEventArgs = Microsoft.IdentityModel.Web.Controls.ErrorEventArgs;

namespace Samples.Saml.ServiceProvider
{
    /// <summary>
    /// The <c>Global</c> class registers event handlers for the Saml2AuthenticationModule.
    /// </summary>
    public class Global : HttpApplication
    {
        protected void Application_Init() {
            // !!! for test ONLY
            new WebClient().DownloadFile(ConfigurationManager.AppSettings["ida:FederationMetadataLocation"], this.Server.MapPath("~/App_Data/sts.xml"));
        }

        /// <summary>
        /// If authorization failed redirect to Identity Provider to re-authenticate rather than show error. 
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="args"><see cref="AuthorizationFailedEventArgs"/> arguments for the event.</param>
        protected void Saml2AuthenticationModule_AuthorizationFailed( object sender, AuthorizationFailedEventArgs args )
        {
            args.RedirectToIdentityProvider = true;
        }
        
        /// <summary>
        /// Occurs when a sign-in error has occurred. 
        /// Provides a chance to handle sign-in error.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e"><see cref="WebErrorEventArgs"/> arguments for the event.</param>
        protected void Saml2AuthenticationModule_SignInError( object sender, WebErrorEventArgs e )
        {
            Context.Items.Add( "Exception", e.Exception );
            Server.Transfer( Request.ApplicationPath + "/Login.aspx" );
        }

        //
        // Other possible events to override:
        // 
        //  - Saml2AuthenticationModule_RedirectingToIdentityProvider
        // Occurs before a SAML message send to identity provider.
        // Can modify SAML message before it will be sent to identity provider.
        // 
        //  - Saml2AuthenticationModule_SecurityTokenReceived
        //  Occurs when a response message with a security token has been received.
        //  Can modify incoming token before validation or perform extra token validation.
        //
        //
        // - Saml2AuthenticationModule_SecurityTokenValidated
        // Occurs when the security token in a response message has been validated.
        // ClaimsPrincipal created from the token can be modified or extra validated.
        //
        //
        // - Saml2AuthenticationModule_SessionSecurityTokenCreated
        // Occurs when a session security token has been created.
        // Can do modification of SessionToken created from incoming token.
        //
        //
        // - Saml2AuthenticationModule_SignedIn
        // Occurs when a user has been authenticated. 
        // Can finish request processing here by redirecting to other page.
        //
        // - Saml2AuthenticationModule_SignedOut;
        // Occurs when a user has been signed out.
        // Can finish request processing here by redirecting to other page.
        //
        // - Saml2AuthenticationModule_SignOutError
        // Occurs when a sign-in error has occurred.
        // Provides a chance to handle sign-out error.
        //
    }
}