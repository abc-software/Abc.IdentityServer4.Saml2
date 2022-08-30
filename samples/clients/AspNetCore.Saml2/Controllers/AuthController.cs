using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.MvcCore;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Authentication;
using Microsoft.AspNetCore.Authentication;
using System.Xml.Linq;

namespace AspNetCore.Saml2.Controllers {
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller {
        const string relayStateReturnUrl = "ReturnUrl";
        private readonly Saml2Configuration config;

        public AuthController(IOptions<Saml2Configuration> configAccessor) {
            config = configAccessor.Value;
        }

        [Route("Login")]
        public IActionResult Login(string returnUrl = null, string accountType = null) {
            var binding = new Saml2PostBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, returnUrl ?? Url.Content("~/") } });

            var saml2Request = new Saml2AuthnRequest(config);

            if (!string.IsNullOrEmpty(accountType)) {
                saml2Request.RequestedAuthnContext = new RequestedAuthnContextEx() {
                    AuthnContextDeclRef = new string[] { accountType },
                };
            }

            return binding.Bind(saml2Request).ToActionResult();
        }

        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService() {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(config);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success) {
                throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
            }
            binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform.Transform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [Route("PostLogout")]
        public async Task<IActionResult> PostLogout() {
            // var binding = new Saml2PostBinding(); // For tests
            var binding = new Saml2RedirectBinding();

            if (binding.IsRequest(Request.ToGenericHttpRequest())) {
                var saml2LogoutRequest = new Saml2LogoutRequest(config);
                binding.ReadSamlRequest(Request.ToGenericHttpRequest(), saml2LogoutRequest);
                binding.Unbind(Request.ToGenericHttpRequest(), saml2LogoutRequest);

                await HttpContext.SignOutAsync(Saml2Constants.AuthenticationScheme);

                var saml2LogoutResponse = new Saml2LogoutResponse(config) { InResponseTo = saml2LogoutRequest.Id };
                binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, Url.Content("~/") } });
                return binding.Bind(saml2LogoutResponse).ToActionResult();
            }

            if (binding.IsResponse(Request.ToGenericHttpRequest())) {
                var saml2LogoutResponse = new Saml2LogoutResponse(config);
                binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2LogoutResponse);
                if (saml2LogoutResponse.Status != Saml2StatusCodes.Success) {
                    throw new AuthenticationException($"SAML Response status: {saml2LogoutResponse.Status}");
                }

                binding.Unbind(Request.ToGenericHttpRequest(), saml2LogoutResponse);
            }

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey(relayStateReturnUrl) ? relayStateQuery[relayStateReturnUrl] : Url.Content("~/");
            return Redirect(returnUrl);
        }

        [HttpPost("Logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout() {
            if (!User.Identity.IsAuthenticated) {
                return Redirect(Url.Content("~/"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = await new Saml2LogoutRequest(config, User).DeleteSession(HttpContext);

            binding.SetRelayStateQuery(new Dictionary<string, string> { { relayStateReturnUrl, Url.Content("~/") } });
            return binding.Bind(saml2LogoutRequest).ToActionResult();
            //return Redirect("~/");
        }

        private class RequestedAuthnContextEx : RequestedAuthnContext {
            public IEnumerable<string> AuthnContextDeclRef { get; set; }
            protected override IEnumerable<XObject> GetXContent() {
                if (Comparison.HasValue) {
                    yield return new XAttribute("Comparison", Comparison.ToString().ToLowerInvariant());
                }

                if (AuthnContextClassRef != null) {
                    foreach (var item in AuthnContextClassRef) {
                        yield return new XElement(Saml2Constants.AssertionNamespaceX + "AuthnContextClassRef", item);
                    }
                }
                else if (AuthnContextDeclRef != null) {
                    foreach (var item in AuthnContextDeclRef) {
                        yield return new XElement(Saml2Constants.AssertionNamespaceX + "AuthnContextDeclRef", item);
                    }
                }
                else {
                    throw new Saml2RequestException();
                }
            }
        }
    }
}
