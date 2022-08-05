using Abc.IdentityServer4.Saml2.Services;
using NUnit.Framework;
using System.Text.Json;

namespace Abc.IdentityServer4.Saml2.UnitTests {
    public class Tests {
        [SetUp]
        public void Setup() {

        }

        [Test]
        public void SerializeDeserialize() {
            var context = new SessionLogoutContext()
            {
                CurrentRealm = "urn:current",
                CurrentRequestId = "12",
                InitialRealm = "urn:init",
                InitialRequestId = "01",
                PartialLogout = "false",
            };

            var str = JsonSerializer.Serialize(context);
        }
    }
}