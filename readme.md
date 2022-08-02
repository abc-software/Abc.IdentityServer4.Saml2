# Abc.IdentityServer4.Saml2

## Overview
Implementation SAML2 IdP support for IdentityServer4 with .NET core.

This is useful for connecting older relying parties to IdentityServer4.

## .NET Support
The underlying SAML2 classes use .NET Core.

## SAML2 endpoint
The SAML2 endpoints is implemented via an `IdentityServer4.Hosting.IEndpointHanlder`.
Endpoint _~/saml2/metadata_ returns SAML2 metadata, _~/saml2_ process SAML2 sing-in and sign-out requests.
This endpoints handles the SAML2P protocol requests and redirects the user to the login page if needed.

The login page will then use the normal return URL mechanism to redirect back to the SAML2 endpoint
to create the protocol response.

## Configuration
For most parts, the SAML2 endpoint can use the standard IdentityServer4 client configuration for relying parties.
But there are also options available for setting SAML2 specific options.

### Defaults
You can configure global defaults in the `Saml2SPOptions` class, e.g.:

* default hashing and digest algorithms
* default SAML name identifier format
* default encryption and keywrap algorithms
* default mappings from "short" claim types to WS-* claim types
* specify Saml2SecurityTokenHandler

### Relying party configuration
The following client settings are used by the SAML2 endpoint:

```csharp
public static IEnumerable<Client> GetClients()
{
    return new[]
    {
        new Client
        {
            // realm identifier
            ClientId = "urn:owinrp",
            
            // must be set to SAML2
            ProtocolType = ProtocolTypes.Saml2p,

            // reply URL
            RedirectUris = { "http://localhost:10313/" },
            
            // signout cleanup url
            LogoutUri = "http://localhost:10313/home/signoutcleanup",
            
            // lifetime of SAML token
            AccessTokenLifetime = 36000,

            // identity scopes - the associated claims will be used to call the profile service
            AllowedScopes = { "openid", "profile" }
        }
    };
}
```

### SAML2 specific relying party settings
If you want to deviate from the global defaults (e.g. set a different token type or claim mapping) for a specific
relying party, you can define a `RelyingParty` object that uses the same realm name as the client ID used above.

This sample contains an in-memory relying party store that you can use to make these relying party specific settings
available to the SAML2 engine (using the `AddInMemoryRelyingParty` extension method).
Otherwise, if you want to use your own store, you will need an implementation of `IRelyingPartyStore`.

### Configuring IdentityServer
This repo contains an extension method for the IdentityServer builder object to register all the necessary services in DI, e.g.:

```csharp
services.AddDistributedMemoryCache();
services.AddIdentityServer()
    .AddSigningCredential(cert)
    .AddInMemoryIdentityResources(Config.GetIdentityResources())
    .AddInMemoryApiResources(Config.GetApiResources())
    .AddInMemoryClients(Config.GetClients())
    .AddTestUsers(TestUsers.Users)
    .AddSaml2()
    .AddAuthorizationParametersMessageStore<DistributedCacheAuthorizationParametersMessageStore>()
    .AddInMemoryRelyingParties(Config.GetRelyingParties());
```

### Enable encrypted SAML2.0 token
Add to project Abc.IdentityModel.Tokens.Saml via nuget and change SecurityTokenHandlers, e.g.:

```csharp
builder.AddSaml2(options => {
    // Add encrypted SAML2.0 tokens support
    options.SecurityTokenHandler = new Abc.IdentityModel.Tokens.Saml2.Saml2SecurityTokenHandler()
    };
});
```

## Connecting a relying party to the SAML2 endpoint

### Using .NET Core
Use the .NET Core SAML2 middleware to point to the SAML2 endpoint, e.g.:

```csharp
public void ConfigureServices(IServiceCollection services) 
{
        services.AddRazorPages();

        services.Configure<Saml2Configuration>(saml2Configuration => {
            saml2Configuration.Issuer = Configuration["saml2:issuer"];
            saml2Configuration.AllowedAudienceUris.Add(saml2Configuration.Issuer);
            saml2Configuration.SignatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            saml2Configuration.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.ChainTrust;
            // !!! REMOVE for production
            saml2Configuration.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            // !!! for TEST only
            saml2Configuration.SaveBootstrapContext = true;

            var entityDescriptor = new EntityDescriptor();
            entityDescriptor.ReadIdPSsoDescriptorFromUrl(new Uri(Configuration["saml2:metadata"]));
            if (entityDescriptor.IdPSsoDescriptor != null) {
                saml2Configuration.SingleSignOnDestination = entityDescriptor.IdPSsoDescriptor.SingleSignOnServices.First().Location;
                saml2Configuration.SingleLogoutDestination = entityDescriptor.IdPSsoDescriptor.SingleLogoutServices.First().Location;
                saml2Configuration.SignatureValidationCertificates.AddRange(entityDescriptor.IdPSsoDescriptor.SigningCertificates);
            }
            else {
                throw new Exception("IdPSsoDescriptor not loaded from metadata.");
            }

            // !!! for ADFS
            saml2Configuration.SignAuthnRequest = true;

            var certPath = Path.Combine(Directory.GetCurrentDirectory(), "saml2.sample.pfx");
            if (!File.Exists(certPath)) {
                throw new InvalidOperationException($"{certPath} not found");
            }

            saml2Configuration.SigningCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, "abc", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);
        });

        services.AddSaml2();
}
```

### Using Katana
Use the Katana SAML2 middleware to point to the SAML2 endpoint, e.g.:

```csharp
public void Configuration(IAppBuilder app)
{
    app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

    app.UseCookieAuthentication(new CookieAuthenticationOptions() {
        CookiePath = HostingEnvironment.ApplicationVirtualPath,
        CookieSameSite = Microsoft.Owin.SameSiteMode.None, 
    });

    app.UseSaml2Authentication(CreateSaml2Options())
}

private static Saml2AuthenticationOptions CreateSaml2Options() {
    var spOptions = new SPOptions {
        EntityId = new EntityId(realm),
        AuthenticateRequestSigningBehavior = SigningBehavior.IfIdpWantAuthnRequestsSigned,
        ReturnUrl = new Uri(System.Web.VirtualPathUtility.ToAbsolute("~/Home"), UriKind.Relative),
    };

    spOptions.ServiceCertificates.Add(new X509Certificate2(
        AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "/App_Data/saml2.sample.pfx", "abc"));

    var saml2Options = new Saml2AuthenticationOptions(false) {
        SPOptions = spOptions
    };

    var ed = MetadataLoader.LoadIdp(adfsMetadata, false);

    var idp = new IdentityProvider(ed.EntityId, spOptions) {
        AllowUnsolicitedAuthnResponse = true,
    };
            
    idp.ReadMetadata(ed);
    saml2Options.IdentityProviders.Add(idp);

    return saml2Options;
}

```

### Using ASP.NET WebForms
Use the WebForms SAML2 module to point to the SAML2 endpoint, e.g.:

```xml
<configuration>
  <configSections>
    <section name="microsoft.identityModel" type="Microsoft.IdentityModel.Configuration.MicrosoftIdentityModelSection, Microsoft.IdentityModel, Version=3.5.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    <section name="microsoft.identityModel.saml" type="Microsoft.IdentityModel.Web.Configuration.MicrosoftIdentityModelSamlSection, Microsoft.IdentityModel.Protocols" />
  </configSections>
  <system.webServer>
    <modules>
        <remove name="FormsAuthentication" />
        <add name="Saml2AuthenticationModule" type="ServiceProvider.MySaml2AuthenticationModule" />
        <add name="SessionAuthenticationModule" type="Microsoft.IdentityModel.Web.SessionAuthenticationModule" />
    </modules>
  </system.webServer>
  <microsoft.identityModel>
    <service>
      <!-- The set of audience URIs. This should match the entityID specified in metadata\homerealmdiscovery.xml. -->
      <audienceUris>
        <add value="urn:sample:saml2:fx" />
      </audienceUris>
      <!-- Enable encrypted tokens -->
      <serviceCertificate>
        <certificateReference x509FindType="FindBySubjectDistinguishedName" findValue="CN=localhost" storeLocation="LocalMachine" storeName="My"/>
      </serviceCertificate>
      <!--!!! Remove in production -->
      <certificateValidation certificateValidationMode="None" />
      <issuerNameRegistry type="Microsoft.IdentityModel.Tokens.ConfigurationBasedIssuerNameRegistry">
        <!-- The set of trusted issuers.  This should match the entityIDs and thumbprints of signing certificates 
             specified in metadata\identityprovider.xml. -->
        <trustedIssuers>
          <add thumbprint="72 49 4c 3a d3 6f 3a 1d 94 7b 38 d1 7e b2 50 57 4c d3 ef 92" name="LVP.STS" />
        </trustedIssuers>
      </issuerNameRegistry>
      <!-- The resolver to use when finding this service's signing and encrypting certificates. -->
      <serviceTokenResolver type="Samples.Saml.Utilities.SampleServiceProviderSecurityTokenResolver" />
      <!-- Enable saveBootstrapTokens so the token visualizer can show the raw SAML assertion. -->
      <securityTokenHandlers>
        <securityTokenHandlerConfiguration saveBootstrapTokens="true">
        </securityTokenHandlerConfiguration>
      </securityTokenHandlers>
      <federatedAuthentication>
        <cookieHandler requireSsl="true" />
      </federatedAuthentication>
    </service>
  </microsoft.identityModel>
</configuration>
 ```