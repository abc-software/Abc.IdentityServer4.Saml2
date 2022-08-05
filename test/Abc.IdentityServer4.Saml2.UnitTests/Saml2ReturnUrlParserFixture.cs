using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityModel.Http;
using Abc.IdentityServer4.Extensions;
using Abc.IdentityServer4.Saml2.Endpoints.UnitTests;
using Abc.IdentityServer4.Saml2.Validation;
using FluentAssertions;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.UnitTests
{
    public class Saml2ReturnUrlParserFixture
    {
        private Saml2ReturnUrlParser _target;

        private MockUserSession _mockUserSession = new MockUserSession();
        private StubSaml2RequestValidator _validator;
        private ILogger<Saml2ReturnUrlParser> _logger = TestLogger.Create<Saml2ReturnUrlParser>();
        private AuthorizationParametersMessageStoreMock _mockAuthorizationParametersMessageStore;
        private HttpSaml2RequestMessage2 _signIn;

        public Saml2ReturnUrlParserFixture()
        {
            _mockAuthorizationParametersMessageStore = new AuthorizationParametersMessageStoreMock();

            _signIn = new HttpSaml2RequestMessage2("https://server/saml2".ToUri(), new Saml2AuthenticationRequest()
            {
                Issuer = new Microsoft.IdentityModel.Tokens.Saml2.Saml2NameIdentifier("client")
            });

            _validator = new StubSaml2RequestValidator();
            _validator.Result = new Saml2RequestValidationResult(new ValidatedSaml2Request() { Saml2RequestMessage = _signIn });

            _target = new Saml2ReturnUrlParser(_mockUserSession, _validator, _logger, null);
        }

        [Theory]
        [InlineData("/saml2/callback?authzId=id")]
        public void returnUrl_valid(string url)
        {
            _target.IsValidReturnUrl(url).Should().BeTrue();
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("https://server/wsfed/callback")]
        [InlineData("/callback")]
        [InlineData("/saml2/callback")]
        public void returnUrl_invalid(string url)
        {
            _target.IsValidReturnUrl(url).Should().BeFalse();
        }

        [Fact]
        public async Task parse_returnUrl_success_from_messagestore()
        {
            _target = new Saml2ReturnUrlParser(_mockUserSession, _validator, _logger, _mockAuthorizationParametersMessageStore);

            _mockAuthorizationParametersMessageStore.Messages.Add("id", new Message<Dictionary<string, string[]>>(new Dictionary<string, string[]>(_signIn.ToDictionary()), DateTime.UtcNow));

            var result = await _target.ParseAsync("/saml2/callback?authzId=id");
            result.Should().NotBeNull();
        }

        //[Fact]
        //public async Task parse_returnUrl_success()
        //{
        //    var serializer = new HttpSaml2MessageSerializer(null);
        //    var returnUrl = serializer.GetRequestUrl(_signIn);

        //    var result = await _target.ParseAsync(returnUrl);
        //    result.Should().NotBeNull();

        //    //result.Client = 
        //}

        //[Fact]
        //public async Task parse_returnUrl_no_signin_request()
        //{
        //    var serializer = new HttpSaml2MessageSerializer(null);
        //    var returnUrl = serializer.GetRequestUrl(_signOut);

        //    var result = await _target.ParseAsync(returnUrl);
        //    result.Should().BeNull();
        //}

        [Fact]
        public async Task parse_returnUrl_validation_error()
        {
            var serializer = new HttpSaml2MessageSerializer(null);
            var returnUrl = serializer.GetRequestUrl(_signIn);
            _validator.Result.IsError = true;

            var result = await _target.ParseAsync(returnUrl);
            result.Should().BeNull();
        }
    }
}
