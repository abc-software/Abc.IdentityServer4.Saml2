// ----------------------------------------------------------------------------
// <copyright file="Saml2LogoutNotificationService.cs" company="ABC software Ltd">
//    Copyright © ABC SOFTWARE. All rights reserved.
//
//    Licensed under the Apache License, Version 2.0.
//    See LICENSE in the project root for license information.
// </copyright>
// ----------------------------------------------------------------------------

using Abc.IdentityModel.Http;
using Abc.IdentityModel.Protocols.Saml2;
using Abc.IdentityServer4.Saml2.ResponseProcessing;
using Abc.IdentityServer4.Saml2.Stores;
using Abc.IdentityServer4.Saml2.Validation;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Abc.IdentityServer4.Saml2.Services
{
    internal class Saml2LogoutNotificationService : ISaml2LogoutNotificationService
    {
        private readonly ILogoutNotificationService _logoutNotificationService;
        private readonly IRelyingPartyStore _relyingPartyStore;
        private readonly ILogoutRequestGenerator _requestGenerator;
        private readonly HttpSaml2MessageSerializer _serializer;
        private readonly ILogger _logger;

        public Saml2LogoutNotificationService(
            ILogoutNotificationService logoutNotificationService, 
            IRelyingPartyStore relyingPartyStore, 
            ILogoutRequestGenerator requestGenerator,
            HttpSaml2MessageSerializer serializer,
            ILogger<Saml2LogoutNotificationService> logger)
        {
            _logoutNotificationService = logoutNotificationService;
            _relyingPartyStore = relyingPartyStore;
            _requestGenerator = requestGenerator;
            _serializer = serializer;
            _logger = logger;
        }

        public async Task<IEnumerable<Saml2LogoutRequest>> GetFrontChannelLogoutNotificationsRequestsAsync(LogoutNotificationContext context)
        {
            var frontChannelRequests = new List<Saml2LogoutRequest>();
            frontChannelRequests.AddRange(
                (await _logoutNotificationService.GetFrontChannelLogoutNotificationsUrlsAsync(context))
                .Select(u => new Saml2LogoutRequest(u, Constants.BindingTypes.RedirectString, u.GetOrigin())));

            // Add SAML2 clients
            foreach (var cid in context.ClientIds)
            {
                var participant = (Saml2SessionParticipant)cid;
                var clientId = participant.ClientId;

                var relyingParty = await _relyingPartyStore.FindRelyingPartyByEntityIdAsync(clientId);
                if (relyingParty is null)
                {
                    continue;
                }

                // support only one
                var sloService = relyingParty.SingleLogoutServices.FirstOrDefault();
                if (sloService == null)
                {
                    _logger.LogWarning($"Cannot generate SLO request for service provider '{clientId}'. Unable to find SLO endpoint with Redirect or POST binding");
                    continue;
                }

                var vr = new Saml2RequestValidationResult(new ValidatedSaml2Request()
                {
                    Subject = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("sub", context.SubjectId) })),
                    RelyingParty = relyingParty,
                    SessionParticipant = participant,
                });

                var sloMessage = await _requestGenerator.GenerateRequestAsync(vr);

                if (sloService.Binding == Saml2Constants.ProtocolBindings.HttpRedirectString)
                {
                    if ((sloMessage.HttpMethods & HttpDeliveryMethods.GetRequest) != HttpDeliveryMethods.GetRequest)
                    {
                        _logger.LogWarning($"Cannot generate SLO request for service provider '{clientId}'.");
                        continue;
                    }

                    var sloRedirectMessage = _serializer.GetRequestUrl(sloMessage);
                    frontChannelRequests.Add(new Saml2LogoutRequest(sloRedirectMessage, Constants.BindingTypes.RedirectString, sloRedirectMessage.GetOrigin()));
                }
                else if (sloService.Binding == Saml2Constants.ProtocolBindings.HttpPostString) 
                {
                    if ((sloMessage.HttpMethods & HttpDeliveryMethods.PostRequest) != HttpDeliveryMethods.PostRequest)
                    {
                        _logger.LogWarning($"Cannot generate SLO request for service provider '{clientId}'.");
                        continue;
                    }

                    string sloPostMessage = _serializer.GetPostBody(sloMessage);

                    // cut <form>...</form> from HTML
                    var startPos = sloPostMessage.IndexOf("<body>");
                    var endPos = sloPostMessage.IndexOf("</form>");
                    var body = sloPostMessage.Substring(startPos + 6, endPos - startPos + 1);

                    frontChannelRequests.Add(new Saml2LogoutRequest(body, Constants.BindingTypes.PostString, sloMessage.BaseUri.OriginalString.GetOrigin()));
                }
            }

            if (frontChannelRequests.Any())
            {
                var msg = frontChannelRequests.Aggregate(
                            new StringBuilder(),
                            (a, b) => a.Append(", ").Append(b),
                            a => a.Remove(0, 2).ToString());
                _logger.LogDebug("Client front-channel logout URLs: {0}", msg);
            }
            else
            {
                _logger.LogDebug("No client front-channel logout URLs");
            }

            return frontChannelRequests;
        }
    }
}