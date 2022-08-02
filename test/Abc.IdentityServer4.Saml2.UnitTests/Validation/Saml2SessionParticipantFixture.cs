using FluentAssertions;
using System;
using Xunit;

namespace Abc.IdentityServer4.Saml2.Validation.UnitTests
{
    public class Saml2SessionParticipantFixture
    {
        [Fact]
        public void Constructor()
        {
            var target = new Saml2SessionParticipant("clientId", new Uri("urn:format"), "nq", "spnq", "nisp", "si");

            target.ClientId.Should().Be("clientId");
            target.NameIdentifierFormat.Should().Be(new Uri("urn:format"));
            target.NameIdentifierNameQualifier.Should().Be("nq");
            target.NameIdentifierSPNameQualifier.Should().Be("spnq");
            target.NameIdentifierSPProvided.Should().Be("nisp");
            target.SessionIndex.Should().Be("si");
        }

        [Fact]
        public void Serialize()
        {
            string str = new Saml2SessionParticipant("clientId", new Uri("urn:format"), "nq", "spnq", "nisp", "si");
            str.Should().Be("clientId;urn:format;nq;spnq;nisp;si");

            var target = (Saml2SessionParticipant)str;

            target.ClientId.Should().Be("clientId");
            target.NameIdentifierFormat.Should().Be(new Uri("urn:format"));
            target.NameIdentifierNameQualifier.Should().Be("nq");
            target.NameIdentifierSPNameQualifier.Should().Be("spnq");
            target.NameIdentifierSPProvided.Should().Be("nisp");
            target.SessionIndex.Should().Be("si");
        }

        [Fact]
        public void Serialize_with_patial_null()
        {
            string str = new Saml2SessionParticipant("clientId", new Uri("urn:format"), null, null, null, "si");
            str.Should().Be("clientId;urn:format;;;;si");

            var target = (Saml2SessionParticipant)str;

            target.ClientId.Should().Be("clientId");
            target.NameIdentifierFormat.Should().Be(new Uri("urn:format"));
            target.NameIdentifierNameQualifier.Should().BeNull();
            target.NameIdentifierSPNameQualifier.Should().BeNull();
            target.NameIdentifierSPProvided.Should().BeNull();
            target.SessionIndex.Should().Be("si");
        }

        [Fact]
        public void Serialize_with_nullable()
        {
            string str = new Saml2SessionParticipant("clientId", null, null, null, null, null);
            str.Should().Be("clientId");

            var target = (Saml2SessionParticipant)str;

            target.ClientId.Should().Be("clientId");
            target.NameIdentifierFormat.Should().BeNull();
            target.NameIdentifierNameQualifier.Should().BeNull();
            target.NameIdentifierSPNameQualifier.Should().BeNull();
            target.NameIdentifierSPProvided.Should().BeNull();
            target.SessionIndex.Should().BeNull();
        }

        [Fact]
        public void Serialize_only_clientid()
        {
            var target = (Saml2SessionParticipant)"clientId";

            target.ClientId.Should().Be("clientId");
            target.NameIdentifierFormat.Should().BeNull();
            target.NameIdentifierNameQualifier.Should().BeNull();
            target.NameIdentifierSPNameQualifier.Should().BeNull();
            target.NameIdentifierSPProvided.Should().BeNull();
            target.SessionIndex.Should().BeNull();
        }

        [Fact]
        public void Serialize_invalid_value()
        {
            Action act = () => { var target = (Saml2SessionParticipant)"clientId;;;;"; };
            act.Should().Throw<FormatException>();
        }
    }
}