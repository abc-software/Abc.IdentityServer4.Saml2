using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Hosting;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class Saml2SingleLogutEndpoint : IEndpointHandler
    {
        private readonly IUserSession _userSession;
        private readonly ILogger _logger;
        private readonly ISamlIdentityServerLogoutMessageStore logoutMessageStore;

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            _logger.LogDebug("Start SAML2P SLO request");

            var ser = new HttpSaml2MessageSerializer(null); // UNDONE: no signature validate
            if (!ser.TryReadMessage<HttpSaml2Message2>(context.Request, out HttpSaml2Message2 incomingMessage))
            {
                return new StatusCodeResult(HttpStatusCode.BadRequest);
            }

            // user can be null here (this differs from HttpContext.User where the anonymous user is filled in)
            var user = await this._userSession.GetUserAsync();

            if (incomingMessage is HttpSaml2RequestMessage2 requestMessage && requestMessage.Saml2Request is Saml2LogoutRequest)
            {
                /*
                //SamlValidationResult validationResult = await requestValidator.Validate(parameters, bindingType, context.Request.GetEncodedUrl(), pathConfiguration.BaseUrl, pathConfiguration.IssuerUri, user);
                //ValidatedSamlMessage validatedMessage = validationResult.ValidatedMessage;
                //if (validationResult.IsError)
                //{
                //    return CreateBackwardsCompatibleErrorResult("Request validation failed", validatedMessage, validationResult.Error, validationResult.ErrorDescription);
                //}

                SamlLogoutMessageStoreResult logoutStoreResult = await logoutMessageStore.Store(validatedMessage.Client, user);
                if (logoutStoreResult.IsError)
                {
                    return CreateBackwardsCompatibleErrorResult("Failed to validate and store IdentityServer logout request", validatedMessage, logoutStoreResult.ErrorMessage, logoutStoreResult.ErrorDescription);
                }

                return new Results.LogoutPageResult(await persistedGrantService.StoreRequest(validationResult.ValidatedMessage), logoutStoreResult.LogoutId);
                */
                var validationResult = await this.signinValidator.ValidateAsync(requestMessage, user);
                if (validationResult.IsError)
                {
                    //return await CreateSignInErrorResult(
                    //    "SAML2 sign in request validation failed",
                    //    validationResult.ValidatedRequest,
                    //    validationResult.Error,
                    //    validationResult.ErrorDescription);
                }

                return new Results.SignOutResult(validationResult.ValidatedRequest);
            }

            if (incomingMessage is HttpSaml2ResponseMessage2 responseMessage && responseMessage.Saml2Response is Saml2LogoutResponse)
            {
                //SamlValidationResult responseValidation = await responseValidator.Validate(parameters, bindingType, context.Request.GetEncodedUrl(), pathConfiguration.BaseUrl, pathConfiguration.IssuerUri, user);
                //if (responseValidation.IsError)
                //{
                //    logger.LogWarning("Received an invalid SLO response from " + responseValidation.ValidatedMessage.Message.Issuer.Id + ".");
                //}
            
                return new StatusCodeResult(HttpStatusCode.OK);
            }

            _logger.LogWarning("Unsupported SAML logout message type.");
            return new StatusCodeResult(HttpStatusCode.OK);
        }

        private async Task<IEndpointResult> ProcessSignoutCompletion(HttpContext context)
        {
            _logger.LogDebug("Start SAML2P SLO completion request");
            if (context.Request.Method == "GET")
            {
                NameValueCollection parameters = nameValueCollectionConverter.Convert(context.Request.Query);
                string requestId = parameters.Get(options.UserInteraction.RequestIdParameter);
                if (requestId == null)
                {
                    return CreateErrorResult("Logout completion request validation failed - missing request ID", null, "Request validation failed", "Missing request ID");
                }

                ValidatedSamlMessage request = await persistedGrantService.GetRequest(requestId);
                if (request == null)
                {
                    return CreateErrorResult("Logout completion request validation failed - invalid request ID", null, "Request validation failed", "Invalid request ID");
                }

                if (request.ResponseDestination == null)
                {
                    return CreateErrorResult("Logout completion request validation failed - request missing response destination", request, "Request validation failed", "Missing response destination");
                }

                GeneratedMessage response;
                if (request.ResponseDestination.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
                {
                    response = await generator.CreatePostBindingResponse(request, pathConfiguration.IssuerUri);
                }
                else
                {
                    if (!(request.ResponseDestination.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"))
                    {
                        return CreateErrorResult("Logout completion request validation failed - unsupported response binding", request, "Unsupported response binding", "Binding type of " + request.ResponseDestination.Binding + " is not supported");
                    }
                    response = await generator.CreateRedirectBindingResponse(request, pathConfiguration.IssuerUri);
                }

                return new Saml2HttpResult(request, response);
            }

            _logger.LogWarning("Invalid HTTP method for SAML2P SLO endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        private async Task<IEndpointResult> ProcessSignoutCallback(HttpContext context)
        {
            _logger.LogDebug("Start SAML2P SLO callback request");
            if (context.Request.Method == "GET")
            {
                NameValueCollection parameters = nameValueCollectionConverter.Convert(context.Request.Query);
                string logoutId = parameters.Get("logoutId");
                if (logoutId == null)
                {
                    return CreateErrorResult("Logout callback request validation failed - missing logout ID", null, "Request validation failed", "Missing logout ID");
                }

                return new SamlEndSessionCallbackResult(await signOutService.GenerateSloUrls(logoutId));
            }

            _logger.LogWarning("Invalid HTTP method for SAML2P SLO endpoint.");
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        private IEndpointResult CreateErrorResult(string logMessage, ValidatedSamlMessage request = null, string error = "server_error", string errorDescription = null, bool logError = true)
        {
            if (logError)
            {
                _logger.LogError(logMessage);
            }
            if (request != null)
            {
                _logger.LogError($"{logMessage}\n{new ValidatedSamlMessageLog(request)}");
            }
            return new Saml2HttpResult(request, new GeneratedPostMessage
            {
                Error = error,
                ErrorDescription = errorDescription
            });
        }
    }
}