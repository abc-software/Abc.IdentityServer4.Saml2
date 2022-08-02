using IdentityServer4.Configuration;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    internal sealed class SessionLogoutContext
    {
        [JsonPropertyName("ir")]
        public string InitialRealm { get; set; }

        [JsonPropertyName("ii")]
        public string InitialRequestId { get; set; }

        [JsonPropertyName("cr")]
        public string CurrentRealm { get; set; }

        [JsonPropertyName("ci")]
        public string CurrentRequestId { get; set; }

        [JsonPropertyName("pl")]
        public string PartialLogout { get; set; }
    }

    internal sealed class SessionParticipantDto
    {
        [JsonPropertyName("r")]
        public string ClientId { get; set; }

        [JsonPropertyName("s1")]
        public string SubjectNameIdentifier { get; set; }

        [JsonPropertyName("s2")]
        public string SubjectNameIdentifierFormat { get; set; }

        [JsonPropertyName("s3")]
        public string SubjectNameIdentifierNameQualifier { get; set; }

        [JsonPropertyName("s4")]
        public string SubjectNameIdentifierSPNameQualifier { get; set; }

        [JsonPropertyName("s5")]
        public string SubjectNameIdentifierSPProvidedId { get; set; }

        [JsonPropertyName("i")]
        public HashSet<string> SessionIndexes { get; set; }
    }

    public class SessionParticipant
    {
        public string ClientId { get; set; }
        public Saml2NameIdentifier SubjectNameIdentifier { get; set; }
        public HashSet<string> SessionIndexes { get; set; }
    }

    public interface ISaml2UserSession
    {
        Task AddClientAsync(string clientId, Saml2NameIdentifier subjectNameIdentifier);

        Task<SessionParticipant> Find(string clientId, Saml2NameIdentifier subjectNameIdentifier);
        Task<SessionParticipant> Find(string clientId, Saml2NameIdentifier subjectNameIdentifier, string sessionIndex);

        Task Remove(string clientId, Saml2NameIdentifier subjectNameIdentifier);
        Task Remove(string clientId, Saml2NameIdentifier subjectNameIdentifier, string sessionIndex);
    }

    public static class AuthenticationPropertiesExtensions
    {
        internal const string Saml2ClientListKey = "saml2_client_list";

        /// <summary>
        /// Gets the list of client ids the user has signed into during their session.
        /// </summary>
        /// <param name="properties"></param>
        /// <returns></returns>
        public static IEnumerable<SessionParticipant> GetSaml2ClientList(this AuthenticationProperties properties)
        {
            if (properties != null && properties.Items.ContainsKey(Saml2ClientListKey))
            {
                return DecodeList(properties.Items[Saml2ClientListKey]);
            }

            return Enumerable.Empty<SessionParticipant>();
        }

        /// <summary>
        /// Sets the list of client ids.
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="clientIds"></param>
        public static void SetSaml2ClientList(this AuthenticationProperties properties, IEnumerable<SessionParticipant> clientIds)
        {
            string value = EncodeList(clientIds);
            if (value == null)
            {
                properties.Items.Remove(Saml2ClientListKey);
            }
            else
            {
                properties.Items[Saml2ClientListKey] = value;
            }
        }

        /// <summary>
        /// Adds a client to the list of clients the user has signed into during their session.
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="clientId"></param>
        public static void AddSaml2ClientId(this AuthenticationProperties properties, SessionParticipant clientId)
        {
            if (clientId is null)
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            var clients = properties.GetSaml2ClientList();
            if (!clients.Contains(clientId))
            {
                var update = clients.ToList();
                update.Add(clientId);
                properties.SetSaml2ClientList(update);
            }
        }

        private static IEnumerable<SessionParticipant> DecodeList(string value)
        {
            //if (value.IsPresent())
            //{
            //    byte[] bytes = Base64Url.Decode(value);
            //    value = Encoding.UTF8.GetString(bytes);
            //    return ObjectSerializer.FromString<string[]>(value);
            //}

            return Enumerable.Empty<SessionParticipant>();
        }

        private static string EncodeList(IEnumerable<SessionParticipant> list)
        {
            if (list != null && list.Any())
            {
                //string value = ObjectSerializer.ToString(list);
                //return Base64Url.Encode(Encoding.UTF8.GetBytes(value));
            }

            return null;
        }
    }

    public class Saml2UserSession : DefaultUserSession, ISaml2UserSession
    {
        public Saml2UserSession(IHttpContextAccessor httpContextAccessor, IAuthenticationHandlerProvider handlers, IdentityServerOptions options, ISystemClock clock, ILogger<IUserSession> logger) 
            : base(httpContextAccessor, handlers, options, clock, logger)
        {
        }

        public async Task AddClientAsync(string clientId, Saml2NameIdentifier subjectNameIdentifier)
        {
            if (clientId is null)
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            await AuthenticateAsync();

            //if (Properties != null && !Properties.GetSaml2ClientList().Contains(clientId))
            //{
            //    Properties.AddSaml2ClientId(clientId);
            //    await UpdateSessionCookie();
            //}
        }

        public Task<SessionParticipant> Find(string clientId, Saml2NameIdentifier subjectNameIdentifier)
        {
            throw new NotImplementedException();
        }

        public Task<SessionParticipant> Find(string clientId, Saml2NameIdentifier subjectNameIdentifier, string sessionIndex)
        {
            throw new NotImplementedException();
        }

        public Task Remove(string clientId, Saml2NameIdentifier subjectNameIdentifier)
        {
            throw new NotImplementedException();
        }

        public Task Remove(string clientId, Saml2NameIdentifier subjectNameIdentifier, string sessionIndex)
        {
            throw new NotImplementedException();
        }
    }
}