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
                    Realm = "urn:owinrp",

                    // SAML1.1 assertion
                    TokenType = WsFederationConstants.TokenTypes.Saml11TokenProfile11,

                    // SHA256
                    DigestAlgorithm = SecurityAlgorithms.Sha256Digest,
                    SignatureAlgorithm = SecurityAlgorithms.RsaSha256Signature,
                    NameIdentifierFormat = WsFederationConstants.SamlNameIdentifierFormats.UnspecifiedString,

                    // WS-Trust2005
                    WsTrustVersion = WsTrustVersion.WsTrust2005,
                },
                new RelyingParty
                {
                    Realm = "urn:aspnetcorerp",

                    // SAML2.0 assertion
                    TokenType = WsFederationConstants.TokenTypes.Saml2TokenProfile11,

                    // SHA512
                    DigestAlgorithm = SecurityAlgorithms.Sha512Digest,
                    SignatureAlgorithm = SecurityAlgorithms.RsaSha512Signature,
                    NameIdentifierFormat = WsFederationConstants.SamlNameIdentifierFormats.UnspecifiedString
                },
                new RelyingParty
                {
                    Realm = "urn:sharepoint",

                    TokenType = WsFederationConstants.TokenTypes.Saml11TokenProfile11,

                    // Transform claim types
                    ClaimMapping = new Dictionary<string, string>
                    {
                        { JwtClaimTypes.Name, ClaimTypes.Name },
                        { JwtClaimTypes.Subject, ClaimTypes.NameIdentifier },
                        { JwtClaimTypes.Email, ClaimTypes.Email },
                        //{ JwtClaimTypes.GivenName, ClaimTypes.GivenName },
                        //{ JwtClaimTypes.FamilyName, ClaimTypes.Surname },
                        //{ JwtClaimTypes.BirthDate, ClaimTypes.DateOfBirth },
                        //{ JwtClaimTypes.WebSite, ClaimTypes.Webpage },
                        //{ JwtClaimTypes.Gender, ClaimTypes.Gender },
                    },

                    //Encryption
                    //EncryptionCertificate = new X509Certificate2(Base64Url.Decode("MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrNA6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEFBQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCHQUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pivqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmbrb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xGvQb3VHSTVVbeei0CfXoW6iz1")),

                    // Defaults
                    DigestAlgorithm = SecurityAlgorithms.Sha256Digest,
                    SignatureAlgorithm = SecurityAlgorithms.RsaSha256Signature,
                    NameIdentifierFormat = WsFederationConstants.SamlNameIdentifierFormats.UnspecifiedString
                }
                */
            };
        }
    }
}