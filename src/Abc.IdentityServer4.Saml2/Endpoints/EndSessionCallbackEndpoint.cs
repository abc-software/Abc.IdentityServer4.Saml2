using Abc.IdentityServer4.Saml2.Services;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Endpoints.Results;
using IdentityServer4.Hosting;
using IdentityServer4.Models;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Endpoints
{
    internal class EndSessionCallbackEndpoint : IEndpointHandler
    {
        //private readonly IEndSessionRequestValidator _endSessionRequestValidator;
        private readonly ILogger _logger;

        public EndSessionCallbackEndpoint(
            //IEndSessionRequestValidator endSessionRequestValidator,
            IMessageStore<LogoutNotificationContext> messageStore,
            ISaml2LogoutNotificationService logoutNotificationService,
            ILogger<EndSessionCallbackEndpoint> logger)
        {
            EndSessionMessageStore = messageStore;
            LogoutNotificationService = logoutNotificationService;
            //_endSessionRequestValidator = endSessionRequestValidator;
            _logger = logger;
        }

        /// <summary>
        /// Gets the logout notification service.
        /// </summary>
        protected ISaml2LogoutNotificationService LogoutNotificationService { get; }

        /// <summary>
        /// Gets the end session message store.
        /// </summary>
        protected IMessageStore<LogoutNotificationContext> EndSessionMessageStore { get; }

        public async Task<IEndpointResult> ProcessAsync(HttpContext context)
        {
            if (!HttpMethods.IsGet(context.Request.Method))
            {
                _logger.LogWarning("Invalid HTTP method for end session callback endpoint.");
                return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
            }

            _logger.LogDebug("Processing signout callback request");

            var endSessionId = context.Request.Query[Constants.DefaultRoutePathParams.EndSessionCallback];
            if (!string.IsNullOrWhiteSpace(endSessionId))
            {
                //return CreateErrorResult("Logout callback request validation failed - missing logout ID", null, "Request validation failed", "Missing logout ID");
            }

            var result = new EndSessionCallbackValidationResult();
            var endSessionMessage = await EndSessionMessageStore.ReadAsync(endSessionId);
            if (endSessionMessage?.Data?.ClientIds?.Any() == true)
            {
                result.FrontChannelLogoutRequests = await LogoutNotificationService.GetFrontChannelLogoutNotificationsRequestsAsync(endSessionMessage.Data);
            }
            else
            {
                result.Error = "Failed to read end session callback message";
            }

            //var parameters = context.Request.Query.AsNameValueCollection();
            //var result = await _endSessionRequestValidator.ValidateCallbackAsync(parameters);

            if (!result.IsError)
            {
                _logger.LogInformation("Successful signout callback.");
            }
            else
            {
                _logger.LogError("Error validating signout callback: {error}", result.Error);
            }

            return new Results.EndSessionCallbackResult(result);
        }
    }
}