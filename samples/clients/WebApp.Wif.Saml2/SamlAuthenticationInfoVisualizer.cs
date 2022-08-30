// ----------------------------------------------------------------------------
// <copyright file="SamlAuthenticationInfoVisualizer.cs" company="ABC software">
//    Copyright © ABC SOFTWARE. All rights reserved.
// </copyright>
// <remarks>
//  Original source from Microsoft Corporation.    
// </remarks>
// ----------------------------------------------------------------------------

namespace Abc.STS.Samples {
    using System;
    using System.Drawing;
    using System.IdentityModel.Selectors;
    using System.IdentityModel.Tokens;
    using System.Text;
    using System.Threading;
    using System.Web;
    using System.Web.UI;
    using System.Web.UI.WebControls;
    using System.Xml;

    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Tokens.Saml2;
    using Microsoft.IdentityModel.Web;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// The <c>SamlAuthenticationInfoVisualizer</c> class displays authentication information obtained from SAML assertion.
    /// </summary>
    public static class SamlAuthenticationInfoVisualizer {
        const string HtmlLineBreak = "<br />";
        static Style captionRowStyle;
        static Style headerRowStyle;
        static Style innerTableStyle;

        /// <summary>
        /// Initializes static members of the <see cref="SamlAuthenticationInfoVisualizer" /> class.
        /// </summary>
        static SamlAuthenticationInfoVisualizer() {
            captionRowStyle = new Style() {
                BackColor = Color.Black,
                ForeColor = Color.White
            };

            captionRowStyle.Font.Bold = true;

            headerRowStyle = new Style() {
                BackColor = Color.Gray,
                ForeColor = Color.White
            };
            headerRowStyle.Font.Bold = true;

            innerTableStyle = new Style() {
                BorderStyle = BorderStyle.Ridge,
                BorderWidth = new Unit(2, UnitType.Pixel)
            };
        }

        static TableCell CreateCell(params Control[] controls) {
            TableCell result = new TableCell();
            foreach (Control control in controls) {
                result.Controls.Add(control);
            }

            return result;
        }

        static TableCell[] CreateCells(params string[] cellsText) {
            TableCell[] result = new TableCell[cellsText.Length];
            for (int i = 0; i < cellsText.Length; i++) {
                result[i] = new TableCell() { Text = cellsText[i] };
            }

            return result;
        }

        static TableRow CreateRow(params TableCell[] cells) {
            TableRow result = new TableRow();
            result.Cells.AddRange(cells);
            return result;
        }

        static Table CreateClaimsIdentityTable(IClaimsIdentity claimsIdentity) {
            Table claimsTable = new Table() {
                ID = "ClaimsIdentityTable",
                GridLines = GridLines.Both
            };

            claimsTable.MergeStyle(innerTableStyle);

            TableRow captionRow = CreateRow(CreateCells("Issued Claims Identity"));
            captionRow.ApplyStyle(captionRowStyle);
            captionRow.Cells[0].ColumnSpan = 3;

            TableRow headerRow = CreateRow(CreateCells("Claim Type", "Claim Value", "Issuer", "Orifinal Issuer"));
            headerRow.ApplyStyle(headerRowStyle);
            claimsTable.Rows.Add(captionRow);
            claimsTable.Rows.Add(headerRow);
            foreach (Claim claim in claimsIdentity.Claims) {
                claimsTable.Rows.Add(CreateRow(CreateCells(SafeHtmlEncode(claim.ClaimType), SafeHtmlEncode(claim.Value), SafeHtmlEncode(claim.Issuer), SafeHtmlEncode(claim.OriginalIssuer))));
            }

            return claimsTable;
        }

        static Table CreateRawAssertionTable(SecurityToken token) {
            Table rawSamlTokenTable = new Table() {
                ID = "RawAssertionTable",
                GridLines = GridLines.Both
            };

            rawSamlTokenTable.ApplyStyle(innerTableStyle);

            TableRow captionRow = CreateRow(CreateCells("Raw SAML11/20 Assertion"));
            captionRow.ApplyStyle(captionRowStyle);
            rawSamlTokenTable.Rows.Add(captionRow);
            string assertionText = @"Cannot retrieve bootstrap token.
If WS-Federation or SAML protocol is used, please enable bootstrap tokens in web.config.

  <microsoft.identityModel>
     <service>
        <securityTokenHandlers>
           <securityTokenHandlerConfiguration saveBootstrapTokens=""true"">
           </securityTokenHandlerConfiguration>
        </securityTokenHandlers>
     </service>
  </microsoft.identityModel>";

            if (token != null) {
                SecurityTokenHandlerCollection securityTokenHandlerCollection = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
                StringBuilder sb = new StringBuilder();
                XmlWriterSettings writerSettings = new XmlWriterSettings() {
                    ConformanceLevel = ConformanceLevel.Fragment,
                    Indent = true,
                    NewLineOnAttributes = true,
                    OmitXmlDeclaration = true
                };
                using (XmlWriter writer = XmlWriter.Create(sb, writerSettings)) {
                    securityTokenHandlerCollection.WriteToken(writer, token);
                    writer.Flush();
                }

                assertionText = sb.ToString();
            }

            TableCell tokenCell = new TableCell() {
                Text = String.Format("<textarea cols=\"120\" rows=\"30\" wrap=\"off\">{0}</textarea>", SafeHtmlEncode(assertionText))
            };

            rawSamlTokenTable.Rows.Add(CreateRow(tokenCell));
            return rawSamlTokenTable;
        }

        static Table CreateSamlAssertionPropertiesTable(Saml2SecurityToken token) {
            Saml2Assertion assertion = token.Assertion;

            Table propertiesTable = new Table() {
                ID = "SamlAssertionPropertiesTable",
                GridLines = GridLines.Both
            };
            propertiesTable.MergeStyle(innerTableStyle);

            TableRow captionRow = CreateRow(CreateCells("Saml2 Assertion Properties"));
            captionRow.ApplyStyle(captionRowStyle);
            captionRow.Cells[0].ColumnSpan = 2;

            TableRow headerRow = CreateRow(CreateCells("Property", "Value"));
            headerRow.ApplyStyle(headerRowStyle);

            string audienceRestriction = "Not recognized";
            if ((assertion.Conditions.AudienceRestrictions.Count == 1) && (assertion.Conditions.AudienceRestrictions[0].Audiences.Count == 1)) {
                audienceRestriction = assertion.Conditions.AudienceRestrictions[0].Audiences[0].AbsoluteUri;
            }

            string nameIdentifier = "Not specified";
            string nameIdentifierformat = "Not specified";
            if (assertion.Subject.NameId != null) {
                nameIdentifier = assertion.Subject.NameId.Value;
                if (assertion.Subject.NameId.Format != null) {
                    nameIdentifierformat = assertion.Subject.NameId.Format.AbsoluteUri;
                }
            }

            propertiesTable.Rows.AddRange(new TableRow[]
            {
                captionRow,
                headerRow,
                CreateRow( CreateCells( "Id", SafeHtmlEncode( assertion.Id.Value ) ) ),
                CreateRow( CreateCells( "Issuer", SafeHtmlEncode( assertion.Issuer.Value ) ) ),
                CreateRow( CreateCells( "IssueInstant", assertion.IssueInstant.ToString() ) ),
                CreateRow( CreateCells( "ValidFrom", assertion.Conditions.NotBefore.HasValue ? assertion.Conditions.NotBefore.Value.ToString() : "Not specified" ) ),
                CreateRow( CreateCells( "ValidTo", assertion.Conditions.NotOnOrAfter.HasValue ? assertion.Conditions.NotOnOrAfter.Value.ToString() : "Not specified" ) ),
                CreateRow( CreateCells( "Audience restriction", SafeHtmlEncode( audienceRestriction ) ) ),
                CreateRow( CreateCells( "NameIdentifier", SafeHtmlEncode( nameIdentifier ) ) ),
                CreateRow( CreateCells( "NameIdentifier format", SafeHtmlEncode( nameIdentifierformat ) ) )
            });

            X509SecurityToken issuerToken = token.IssuerToken as X509SecurityToken;
            if (issuerToken != null) {
                string signingCertificateString = issuerToken.Certificate.ToString(false).Replace("\r\n\r\n", HtmlLineBreak);

                propertiesTable.Rows.Add(CreateRow(CreateCells("Signature Algorithm", assertion.SigningCredentials.SignatureAlgorithm)));
                propertiesTable.Rows.Add(CreateRow(CreateCells("Signing certificate", signingCertificateString)));
            }

            if (assertion.EncryptingCredentials != null) {
                EncryptedKeyIdentifierClause clause = assertion.EncryptingCredentials.SecurityKeyIdentifier[0] as EncryptedKeyIdentifierClause;
                SecurityTokenResolver decryptionTokenResolver = FederatedAuthentication.ServiceConfiguration.ServiceTokenResolver;
                X509SecurityToken encryptionToken = decryptionTokenResolver.ResolveToken(clause.EncryptingKeyIdentifier) as X509SecurityToken;
                string encryptingCertificateString = encryptionToken.Certificate.ToString(false).Replace("\r\n\r\n", HtmlLineBreak);
                propertiesTable.Rows.Add(CreateRow(CreateCells("Encryption Algorithm", assertion.EncryptingCredentials.Algorithm)));
                propertiesTable.Rows.Add(CreateRow(CreateCells("Encrypting certificate", encryptingCertificateString)));
            }

            return propertiesTable;
        }

        static Table CreateSamlAssertionPropertiesTable(SamlSecurityToken token) {
            SamlAssertion assertion = token.Assertion;

            Table propertiesTable = new Table() {
                ID = "SamlAssertionPropertiesTable",
                GridLines = GridLines.Both
            };

            propertiesTable.MergeStyle(innerTableStyle);

            TableRow captionRow = CreateRow(CreateCells("Saml11 Assertion Properties"));
            captionRow.ApplyStyle(captionRowStyle);
            captionRow.Cells[0].ColumnSpan = 2;

            TableRow headerRow = CreateRow(CreateCells("Property", "Value"));
            headerRow.ApplyStyle(headerRowStyle);

            string audienceRestriction = "Not recognized";
            if (assertion.Conditions != null) {
                foreach (var condition in assertion.Conditions.Conditions) {
                    var audienceRestrictionCondition = condition as SamlAudienceRestrictionCondition;
                    if (audienceRestrictionCondition != null) {
                        audienceRestriction = audienceRestrictionCondition.Audiences[0].AbsoluteUri;
                        break;
                    }
                }
            }

            string nameIdentifier = "Not specified";
            string nameIdentifierformat = "Not specified";
            foreach (var statement in assertion.Statements) {
                var subjectStatement = statement as SamlSubjectStatement;
                if (subjectStatement != null) {
                    SamlSubject subject = subjectStatement.SamlSubject;
                    nameIdentifier = subject.Name;
                    nameIdentifierformat = subject.NameFormat;
                    break;
                }
            }

            propertiesTable.Rows.AddRange(new TableRow[]
            {
                captionRow,
                headerRow,
                CreateRow( CreateCells( "Id", SafeHtmlEncode( assertion.AssertionId) ) ),
                CreateRow( CreateCells( "Issuer", SafeHtmlEncode( assertion.Issuer) ) ),
                CreateRow( CreateCells( "IssueInstant", assertion.IssueInstant.ToString() ) ),
                CreateRow( CreateCells( "ValidFrom", assertion.Conditions != null && assertion.Conditions.NotBefore != new DateTime(DateTime.MinValue.Ticks + 0xc92a69c000L, DateTimeKind.Utc) ? assertion.Conditions.NotBefore.ToString() : "Not specified") ),
                CreateRow( CreateCells( "ValidTo", assertion.Conditions != null && assertion.Conditions.NotOnOrAfter != new DateTime(DateTime.MaxValue.Ticks - 0xc92a69c000L, DateTimeKind.Utc) ? assertion.Conditions.NotOnOrAfter.ToString() : "Not specified") ),
                CreateRow( CreateCells( "Audience restriction", SafeHtmlEncode( audienceRestriction ) ) ),
                CreateRow( CreateCells( "NameIdentifier", SafeHtmlEncode( nameIdentifier ) ) ),
                CreateRow( CreateCells( "NameIdentifier format", SafeHtmlEncode( nameIdentifierformat ) ) )
            });

            X509SecurityToken issuerToken = assertion.SigningToken as X509SecurityToken;
            if (issuerToken != null) {
                string signingCertificateString = issuerToken.Certificate.ToString(false).Replace("\r\n\r\n", HtmlLineBreak);

                propertiesTable.Rows.Add(CreateRow(CreateCells("Signature Algorithm", assertion.SigningCredentials.SignatureAlgorithm)));
                propertiesTable.Rows.Add(CreateRow(CreateCells("Signing certificate", signingCertificateString)));
            }

            return propertiesTable;
        }

        static string SafeHtmlEncode(string input) {
            if (String.IsNullOrEmpty(input)) {
                return String.Empty;
            }

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < input.Length; i++) {
                sb.AppendFormat("&#{0};", ((int)input[i]).ToString());
            }

            return sb.ToString();
        }

        /// <summary>
        /// Creates the table with authentication information.
        /// </summary>
        /// <returns>Table for display.</returns>
        public static Table Create() {
            Table result = new Table();
            result.Rows.Add(CreateRow(CreateCells(HtmlLineBreak)));

            IClaimsIdentity claimsIdentity = Thread.CurrentPrincipal.Identity as IClaimsIdentity;
            if (claimsIdentity != null) {
                result.Rows.Add(CreateRow(CreateCell(CreateClaimsIdentityTable(claimsIdentity))));
                result.Rows.Add(CreateRow(CreateCells(HtmlLineBreak)));

                var token = claimsIdentity.BootstrapToken;
                if (token is SamlSecurityToken) {
                    result.Rows.Add(CreateRow(CreateCell(CreateSamlAssertionPropertiesTable((SamlSecurityToken)token))));
                }
                else if (token is Saml2SecurityToken) {
                    result.Rows.Add(CreateRow(CreateCell(CreateSamlAssertionPropertiesTable((Saml2SecurityToken)token))));
                }

                result.Rows.Add(CreateRow(CreateCells(HtmlLineBreak)));
                result.Rows.Add(CreateRow(CreateCell(CreateRawAssertionTable(token))));
            }

            return result;
        }
    }
}
