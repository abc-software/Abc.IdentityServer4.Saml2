using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Services;
using FluentAssertions;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Services.UnitTests
{
    public class Saml2LogoutNotificationServiceFixture
    {
        public Saml2LogoutNotificationServiceFixture()
        {

            _subject = new Saml2LogoutNotificationService(
               _logoutNotificationService,
               _relyingPartyStore,
               _requestGenerator,
               _serialzier,
               TestLogger<Saml2LogoutNotificationService>()
                );
        }
    }
}
