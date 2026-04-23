#if DUENDE
global using Duende.IdentityServer.Hosting;
global using Duende.IdentityServer.Models;
global using Duende.IdentityServer.Stores;
global using Duende.IdentityServer.Configuration;
global using Duende.IdentityServer.Extensions;
global using Duende.IdentityServer.Services;
global using Duende.IdentityServer.Events;
global using Duende.IdentityServer.ResponseHandling;
global using Duende.IdentityServer.Test;
global using Ids = Duende.IdentityServer;
global using StatusCodeResult = Duende.IdentityServer.Endpoints.Results.StatusCodeResult;
#else
global using IdentityServer4.Hosting;
global using IdentityServer4.Models;
global using IdentityServer4.Stores;
global using IdentityServer4.Configuration;
global using IdentityServer4.Extensions;
global using IdentityServer4.Services;
global using IdentityServer4.Events;
global using IdentityServer4.ResponseHandling;
global using IdentityServer4.Test;
global using Ids = IdentityServer4;
global using StatusCodeResult = IdentityServer4.Endpoints.Results.StatusCodeResult;
#endif

#if NET8_0_OR_GREATER && DUENDE
global using Duende.IdentityModel.Client;
#else
global using IdentityModel.Client;
#endif