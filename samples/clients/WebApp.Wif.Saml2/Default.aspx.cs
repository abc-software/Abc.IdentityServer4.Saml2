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
using System.Threading;
using System.Web.UI;
using System.Linq;
using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.Web;

namespace Samples.Saml.ServiceProvider
{
    /// <summary>
    /// The default page requires the user to be authenticated and provides a logout link.
    /// </summary>
    public partial class _Default : Page
    {
        /// <summary>
        /// Page load event handler.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        protected void Page_Load( object sender, EventArgs e )
        {
            IClaimsIdentity claimsIdentity = Thread.CurrentPrincipal.Identity as IClaimsIdentity;
            String name = (from c in claimsIdentity.Claims
                           where c.ClaimType == Microsoft.IdentityModel.Claims.ClaimTypes.NameIdentifier
                           select c.Value).SingleOrDefault();
            if (!String.IsNullOrEmpty(name))
            {
                username.Text = Server.HtmlEncode("as " + name);
            }
            DefaultForm.Controls.Add( Abc.STS.Samples.SamlAuthenticationInfoVisualizer.Create() );
        }

        /// <summary>
        /// Logout button event handler.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        protected void Logout_Click( object sender, EventArgs e )
        {
            Saml2AuthenticationModule.Current.SignOut( "~/Login.aspx" );
        }
    }
}
