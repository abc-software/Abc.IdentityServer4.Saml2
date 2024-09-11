#if DUENDE
global using Duende.IdentityServer.EntityFramework.DbContexts;
global using Duende.IdentityServer.EntityFramework.Interfaces;
global using Duende.IdentityServer.EntityFramework.Options;
global using Duende.IdentityServer.EntityFramework.Stores;
global using Duende.IdentityServer.Services;
global using IdsEntities = Duende.IdentityServer.EntityFramework.Entities;
#else
global using IdentityServer4.EntityFramework.DbContexts;
global using IdentityServer4.EntityFramework.Interfaces;
global using IdentityServer4.EntityFramework.Options;
global using IdentityServer4.EntityFramework.Stores;
global using IdsEntities = IdentityServer4.EntityFramework.Entities;
#endif