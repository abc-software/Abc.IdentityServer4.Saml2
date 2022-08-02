﻿using FluentAssertions;
using IdentityServer4.Extensions;
using Microsoft.AspNetCore.Http;
using Sustainsys.Saml2.Metadata;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Endpoints.Results.UnitTests
{
    public class MetadataResultFixture
    {
        private MetadataBase _metadata;
        private MetadataResult _target;
        private DefaultHttpContext _context;

        public MetadataResultFixture()
        {
            _context = new DefaultHttpContext();
            _context.SetIdentityServerOrigin("https://server");
            _context.SetIdentityServerBasePath("/");
            _context.Response.Body = new MemoryStream();

            _metadata = new EntityDescriptor(new EntityId("urn:issuer"));

            _target = new MetadataResult(_metadata);
        }

        [Fact]
        public void metadata_ctor()
        {
            Action action = () =>
            {
                _target = new MetadataResult(null);
            };

            action.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public async Task metadata_should_pass_results_in_body()
        {
            await _target.ExecuteAsync(_context);
            _context.Response.StatusCode.Should().Be(200);
            _context.Response.ContentType.Should().Contain("application/samlmetadata+xml");

            _context.Response.Body.Seek(0, SeekOrigin.Begin);
            using (var rdr = new StreamReader(_context.Response.Body))
            {
                var xml = rdr.ReadToEnd();
                xml.Should().Contain(@"<EntityDescriptor entityID=""urn:issuer""");
            }
        }
    }
}