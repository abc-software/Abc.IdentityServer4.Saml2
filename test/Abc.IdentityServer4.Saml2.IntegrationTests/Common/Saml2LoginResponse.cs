using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Xml.Linq;
using System.Xml;
using System.Xml.XPath;

namespace Abc.IdentityServer4.Saml2.IntegrationTests.Common
{
    public class Saml2LoginResponse
    {
        private readonly string action;

        public IDictionary<string, string> Items { get; }

        public string Action => action;

        public string SessionIndex
        {
            get
            {
                var data = XDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(Items["SAMLResponse"])));
                var namespaceManager = new XmlNamespaceManager(new NameTable());
                namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
                namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");

                var sessionIndex = data.XPathSelectElement(@"/samlp:Response/saml:Assertion/saml:AuthnStatement", namespaceManager)
                    .Attribute("SessionIndex").Value;

                return sessionIndex;
            }
        }

        public Saml2LoginResponse(string html)
        {
            Items = AnalysePost(html, out action);
        }

        private Dictionary<string, string> AnalysePost(string html, out string action)
        {
            action = null;
            var match = new Regex(@"action=""(?<action>.+?)""").Match(HttpUtility.HtmlDecode(html));
            if (match.Success)
            {
                action = match.Groups["action"].Value;
            }

            var collection = new Dictionary<string, string>();
            var mathces = new Regex(@"<input type=""hidden"" name=""(?<name>.+?)"" value=""(?<value>.+?)"" />").Matches(HttpUtility.HtmlDecode(html));
            foreach (Match m in mathces)
            {
                collection.Add(m.Groups["name"].Value, m.Groups["value"].Value);
            }

            return collection;
        }
    }
}
