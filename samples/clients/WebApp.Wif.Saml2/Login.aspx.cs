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

using System;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Web;

namespace Samples.Saml.ServiceProvider {
    /// <summary>
    /// The login page does not require authentication and provides a login link.
    /// </summary>
    public partial class Login : Page {
        /// <summary>
        /// Page load event.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        protected void Page_Load(object sender, EventArgs e) {
            object exceptionObject = Context.Items["Exception"];
            if (exceptionObject != null) {
                Exception exception = exceptionObject as Exception;
                if (exception != null) {
                    ErrorLabel.Text = "Error: " + exception.Message;
                    ErrorLabel.Visible = true;
                }
            }
        }

        /// <summary>
        /// Login button click handler.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        protected void Login_Click(object sender, EventArgs e) {
            // Use MySaml2AuthenticationModule to get identityProvider from meta-data
            Saml2AuthenticationModule.Current.SignIn("~/Default.aspx", null, null);
        }
    }
}
