using Abc.IdentityServer4.Saml2.Stores;
using IdentityModel;
using IdentityServer4.Models;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Claims;
using static IdentityServer4.IdentityServerConstants;

namespace IdentityServer4.WsFederation
{
    public static class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new[]
            {
                new IdentityResources.OpenId(),
                new IdentityResource("profile", new[] { JwtClaimTypes.Name, JwtClaimTypes.Email })
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new[]
            {
                new ApiResource("api1", "Some API 1"),
                new ApiResource("api2", "Some API 2")
            };
        }

        public static IEnumerable<ApiScope> GetApiScopes()
        {
            return new[]
            {
                new ApiScope("api1", "My API 1"),
                new ApiScope("api2", "My API 2"),
            };
        }


        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                new Client
                {
                    ClientId = "urn:owinrp", // entityId identifier
                    ProtocolType = ProtocolTypes.Saml2p, // must be set to SAML2

                    RedirectUris = { "https://localhost:44334/Saml2/Acs" }, // reply URL
                    PostLogoutRedirectUris = { "https://localhost:44334/" }, 
                    FrontChannelLogoutUri = "https://localhost:44334/Saml2/Acs",
                    AccessTokenLifetime = 36000, // lifetime of SAML2 token

                    AllowedScopes = { "openid", "profile" }
                },
                new Client
                {
                    ClientId = "urn:aspnetcorerp",
                    ProtocolType = ProtocolTypes.Saml2p,

                    RedirectUris = { "https://localhost:44302/Auth/AssertionConsumerService" },
                    PostLogoutRedirectUris = { "https://localhost:44302/Auth/PostLogout" },
                    FrontChannelLogoutUri = "https://localhost:44302/Auth/Logout",
                    AccessTokenLifetime = 36000,

                    AllowedScopes = { "openid", "profile" }
                },
                new Client
                {
                    ClientId = "urn:aspnetwebapprp",
                    ProtocolType = ProtocolTypes.Saml2p,

                    RedirectUris = { "https://localhost:44314/Default.aspx" },
                    PostLogoutRedirectUris = { "https://localhost:44314/Default.aspx" },
                    FrontChannelLogoutUri = "https://localhost:44314/Default.aspx",
                    AccessTokenLifetime = 36000,

                    AllowedScopes = { "openid", "profile" }
                },
            };
        }

        public static IEnumerable<RelyingParty> GetRelyingParties()
        {
            return new RelyingParty[]
            {   
                /*
                new RelyingParty
                {
                    EntityId = "urn:owinrp",

                    // SHA256
                    DigestAlgorithm = SecurityAlgorithms.Sha256Digest,
                    SignatureAlgorithm = SecurityAlgorithms.RsaSha256Signature,
                },
                new RelyingParty
                {
                    EntityId = "urn:aspnetcorerp",

                    // SHA512
                    DigestAlgorithm = SecurityAlgorithms.Sha512Digest,
                    SignatureAlgorithm = SecurityAlgorithms.RsaSha512Signature,
                },
                */
            };
        }
    }
}