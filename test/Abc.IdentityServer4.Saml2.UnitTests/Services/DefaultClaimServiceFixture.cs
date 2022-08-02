using FluentAssertions;
using IdentityModel;
using IdentityServer4;
using IdentityServer4.Configuration;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Xunit;
using MockProfileService = IdentityServer4.Services.MockProfileService;

namespace Abc.IdentityServer4.Saml2.Services.UnitTests
{
    public class DefaultClaimServiceFixture
    {
        private DefaultClaimsService _target;
        private ValidatedRequest _validatedRequest;
        private MockProfileService _mockMockProfileService = new MockProfileService();
        private Client _client;
        private ClaimsPrincipal _user;

        public DefaultClaimServiceFixture()
        {
            _client = new Client
            {
                ClientId = "client",
                Claims = { new ClientClaim("some_claim", "some_claim_value") }
            };

            _user = new IdentityServerUser("bob")
            {
                IdentityProvider = "idp",
                AuthenticationMethods = { OidcConstants.AuthenticationMethods.Password },
                AuthenticationTime = new System.DateTime(2000, 1, 1),
            }.CreatePrincipal();

            _target = new DefaultClaimsService(_mockMockProfileService, TestLogger.Create<DefaultClaimsService>());

            _validatedRequest = new ValidatedRequest();
            _validatedRequest.Subject = _user;
            _validatedRequest.Options = new IdentityServerOptions();
            _validatedRequest.SetClient(_client);
        }

        [Fact]
        public async Task GetClaimsAsync_should_return_profile_user_claims()
        {
            _mockMockProfileService.ProfileClaims.Add(new Claim(JwtClaimTypes.Subject, "sub"));

            var requestedClaimTypes = new string[0];
            var claims = await _target.GetClaimsAsync(_validatedRequest, requestedClaimTypes);

            var types = claims.Select(x => x.Type);
            types.Should().Contain(JwtClaimTypes.Subject);
        }

        [Fact]
        public void MapAsync_should_return_mapped_saml2_claims()
        {
            var claims = new List<Claim>() {
                new Claim(JwtClaimTypes.Subject, "sub"),
                new Claim(JwtClaimTypes.Name, "bob").AddProperty("property", "p_val"),
                new Claim(JwtClaimTypes.NickName, "bob_nick"),
            };

            var mapping = new Dictionary<string, string>()
            {
                { JwtClaimTypes.Subject, "urn:nameidentifier" },
                { JwtClaimTypes.Name, "http://test.org/name" },
            };

            var mappedClaims = _target.MapClaims(mapping, claims);

            var expected = new List<Claim>() {
                new Claim("urn:nameidentifier", "sub").AddProperty("http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName", JwtClaimTypes.Subject),
                new Claim("http://test.org/name", "bob").AddProperty("http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName", JwtClaimTypes.Name).AddProperty("property", "p_val"),
                new Claim(JwtClaimTypes.NickName, "bob_nick"),
            };

            mappedClaims.Should().BeEquivalentTo(expected);
        }
    }
}