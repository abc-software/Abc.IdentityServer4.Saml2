using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.ResponseProcessing
{
    internal class LogoutResponseGenerator : ILogoutResponseGenerator
    {
        private readonly ILogger _logger;
        private readonly Saml2SPOptions _options;
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IKeyMaterialService _keys;
        private readonly ISystemClock _clock;

        public LogoutResponseGenerator(
            ILogger<LogoutResponseGenerator> logger,
            Saml2SPOptions options,
            IHttpContextAccessor contextAccessor,
            IKeyMaterialService keys,
            ISystemClock clock)
        {
            _logger = logger;
            _options = options;
            _contextAccessor = contextAccessor;
            _keys = keys;
            _clock = clock;
        }

        public async Task<HttpSaml2Message2> GenerateResponseAsync(Saml2RequestValidationResult validationResult)
        {
            _logger.LogDebug("Creating SAML2 signout response");

            var validatedRequest = validationResult.ValidatedRequest;

            var credentials = await _keys.GetX509SigningCredentialsAsync();
            var issuer = _contextAccessor.HttpContext.GetIdentityServerIssuerUri();
            var issueInstant = _clock.UtcNow.UtcDateTime;

            var signingCredentials = new SigningCredentials(
                credentials.Key,
                validatedRequest.RelyingParty?.SignatureAlgorithm ?? _options.DefaultSignatureAlgorithm,
                validatedRequest.RelyingParty?.DigestAlgorithm ?? _options.DefaultDigestAlgorithm);

            var logoutRequest = validatedRequest.Saml2RequestMessage.Saml2Request as Saml2LogoutRequest;
            var singleSignOutService = validationResult.ValidatedRequest.RelyingParty?.SingleLogoutServices.FirstOrDefault();
            var destination = singleSignOutService?.Location ?? validatedRequest.ReplyUrl;

            var logoutResponse = new Saml2LogoutResponse(new Saml2Status(Saml2StatusCode.Success))
            {
                InResponseTo = logoutRequest.Id,
                Issuer = new Saml2NameIdentifier(issuer),
                SigningCredentials = signingCredentials,
                IssueInstant = issueInstant,
                Destination = new Uri(destination),
            };

            var method =
                string.Equals(singleSignOutService?.Binding, Abc.IdentityModel.Protocols.Saml2.Saml2Constants.ProtocolBindings.HttpPostString)
                ? HttpDeliveryMethods.PostRequest
                : HttpDeliveryMethods.GetRequest;

            return new HttpSaml2ResponseMessage2(logoutResponse.Destination, logoutResponse, method)
            {
                RelayState = validatedRequest.Saml2RequestMessage.RelayState,
            };
        }
    }
}