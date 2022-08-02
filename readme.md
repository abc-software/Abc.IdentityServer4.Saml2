# Abc.IdentityServer4.Security
**Sample** for implementing [JWT Response for OAuth Token Introspection](https://tools.ietf.org/html/draft-ietf-oauth-jwt-introspection-response-08) support for IdentityServer4 with .NET core.

### Configuring IdentityServer
This repo contains an extension method for the IdentityServer builder object to register all the necessary services in DI, e.g.:

```csharp
services.AddIdentityServerWithJwtIntrospection()
    .AddSigningCredential(cert)
    .AddInMemoryIdentityResources(Config.GetIdentityResources())
    .AddInMemoryApiResources(Config.GetApiResources())
    .AddInMemoryClients(Config.GetClients())
    .AddTestUsers(TestUsers.Users)
    .AddInMemoryRelyingParties(Config.GetRelyingParties());
```
