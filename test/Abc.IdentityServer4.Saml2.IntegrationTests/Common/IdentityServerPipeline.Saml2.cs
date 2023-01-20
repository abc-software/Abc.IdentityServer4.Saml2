using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Xml;

namespace Abc.IdentityServer4.Saml2.IntegrationTests.Common
{
    public partial class IdentityServerPipeline
    {
        public const string Saml2SingleSignOnEndpoint = BaseUrl + "/saml2";
        public const string Saml2SingleSignOnCallbackEndpoint = BaseUrl + "/saml2/callback";
        public const string Saml2SingleLogOutCallbackEndpoint = BaseUrl + "/saml2/slo/callback";
        public const string Saml2MetadataEndpoint = BaseUrl + "/saml2/metadata";
        public const string Saml2ArtifactResolutionEndpoint = BaseUrl + "/saml2/ars";
        public const string Saml2EndSessionCallbackEndpoint = BaseUrl + "/saml2/endsession/callback";

        public string CreateLoginUrl(
            string clientId,
            string redirectUri = null,
            string state = null,
            string responseMode = null
           )
        {
            var str = $@"
<samlp:AuthnRequest 
    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" 
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" 
    ID=""_{Guid.NewGuid().ToString("N")}"" 
    Version=""2.0"" 
    IssueInstant=""{XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc)}"" 
    Destination=""{Saml2SingleSignOnEndpoint}"" 
    AssertionConsumerServiceURL=""{redirectUri}"" 
    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"">
    <saml:Issuer>{clientId}</saml:Issuer>
</samlp:AuthnRequest>";

            return CreateUrl(str, state);
        }

        public string CreateLogoutUrl(
            string clientId,
            string subjectId,
            string state = null,
            string sessionIndex = null
           )
        {
            var str = $@"
<samlp:LogoutRequest 
    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" 
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" 
    ID=""_{Guid.NewGuid().ToString("N")}"" 
    Version=""2.0"" 
    IssueInstant=""{XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc)}"" 
    Destination=""{Saml2SingleSignOnEndpoint}"">
    <saml:Issuer>{clientId}</saml:Issuer>
    <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">{subjectId}</saml:NameID>
    <samlp:SessionIndex>{sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>";

            return CreateUrl(str, state);
        }

        public FormUrlEncodedContent FormUrlEncodedContent(
            string clientId,
            string redirectUri = null,
            string state = null,
            string responseMode = null
           )
        {
            var str = $@"
<samlp:AuthnRequest 
    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" 
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" 
    ID=""_{Guid.NewGuid().ToString("N")}"" 
    Version=""2.0"" 
    IssueInstant=""{XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc)}"" 
    Destination=""{Saml2SingleSignOnEndpoint}"" 
    AssertionConsumerServiceURL=""{redirectUri}"" 
    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"">
    <saml:Issuer>{clientId}</saml:Issuer>
</samlp:AuthnRequest>";

            return CreatePost(str, state);
        }

        public FormUrlEncodedContent CreateLogotPost(
            string clientId,
            string subjectId,
            string state = null,
            string sessionIndex = null
           )
        {
            var str = $@"
<samlp:LogoutRequest 
    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol"" 
    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion"" 
    ID=""_{Guid.NewGuid().ToString("N")}"" 
    Version=""2.0"" 
    IssueInstant=""{XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc)}"" 
    Destination=""{Saml2SingleSignOnEndpoint}"">
    <saml:Issuer>{clientId}</saml:Issuer>
    <saml:NameID Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"">{subjectId}</saml:NameID>
    <samlp:SessionIndex>{sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>";

            return CreatePost(str, state);
        }

        private string CreateUrl(string str, string state)
        {
            var values = new Dictionary<string, string>
            {
                { "SAMLRequest", DeflateEncode(str) },
                { "RelayState", state }
            };

            var url = new RequestUrl(Saml2SingleSignOnEndpoint);
            return url.Create(values);

            static string DeflateEncode(string data)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(data);
                using MemoryStream memoryStream = new MemoryStream();
                using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Compress, leaveOpen: true))
                {
                    deflateStream.Write(bytes, 0, bytes.Length);
                }

                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }

        private FormUrlEncodedContent CreatePost(string str, string state)
        {
            var values = new Dictionary<string, string>
            {
                { "SAMLRequest", Convert.ToBase64String(Encoding.UTF8.GetBytes(str)) },
                { "RelayState", state }
            };

            return new FormUrlEncodedContent(values);
        }
    }
}
