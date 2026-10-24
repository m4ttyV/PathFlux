using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Policy.Tests;

public sealed class UdpVerificationPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 24, 12, 0, 0, TimeSpan.Zero);
    private static ProxyProfile Profile() => new()
    {
        Id = Guid.Parse("6d3fe982-fdee-42a9-9525-edbb35ecbabe"),
        Name = "Local SOCKS", Host = "proxy.example", Port = 1080, CredentialsRef = "opaque-secret-reference"
    };
    private static ProxyProfile Verified(ProxyProfile? source = null)
    {
        var profile = source ?? Profile();
        return profile with { UdpVerification = new(UdpVerificationPolicy.Fingerprint(profile), Now,
            UdpRelayStatus.Verified, "192.0.2.25", 30999, 3, 3, 4.5) };
    }

    [Fact]
    public void DisplayChangesAndEnableTogglePreserveHistoricalRelayIdentity()
    {
        var profile = Verified();
        var changed = profile with { Name = "Renamed profile", Enabled = false };
        Assert.Equal(UdpVerificationPolicy.Fingerprint(profile), UdpVerificationPolicy.Fingerprint(changed));
        Assert.True(UdpVerificationPolicy.IsCurrent(changed, Now));
    }

    [Fact]
    public void HostCaseAndWhitespaceDoNotInvalidateAnEquivalentFingerprint()
    {
        var profile = Verified();
        var changed = profile with { Host = " PROXY.EXAMPLE " };
        Assert.Equal(UdpVerificationPolicy.Fingerprint(profile), UdpVerificationPolicy.Fingerprint(changed));
        Assert.True(UdpVerificationPolicy.IsCurrent(changed, Now));
    }

    public static IEnumerable<object[]> IdentityChanges()
    {
        yield return [Profile() with { Id = Guid.Parse("da0166f0-823c-4bc4-86bd-28286cf58191") }];
        yield return [Profile() with { Host = "other.example" }];
        yield return [Profile() with { Port = 2080 }];
        yield return [Profile() with { CredentialsRef = "replacement-secret-reference" }];
        yield return [Profile() with { CredentialsRef = null }];
        yield return [Profile() with { Protocol = ProxyProtocol.HttpConnect }];
        yield return [Profile() with { TlsServerName = "tls.example" }];
    }

    [Theory]
    [MemberData(nameof(IdentityChanges))]
    public void ConnectionIdentityChangesInvalidateOldEvidence(ProxyProfile changed)
    {
        var original = Verified();
        Assert.NotEqual(UdpVerificationPolicy.Fingerprint(original), UdpVerificationPolicy.Fingerprint(changed));
        Assert.False(UdpVerificationPolicy.IsCurrent(changed with { UdpVerification = original.UdpVerification }, Now));
    }

    [Fact]
    public void EvidenceDoesNotContributeToItsOwnFingerprint()
    {
        var profile = Profile();
        Assert.Equal(UdpVerificationPolicy.Fingerprint(profile), UdpVerificationPolicy.Fingerprint(Verified(profile)));
        Assert.Equal(UdpVerificationPolicy.Fingerprint(profile), UdpVerificationPolicy.Fingerprint(profile with
        {
            UdpVerification = Verified(profile).UdpVerification! with { ProfileFingerprint = "malformed", Status = UdpRelayStatus.Failed }
        }));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(899, true)]
    [InlineData(900, true)]
    [InlineData(901, false)]
    [InlineData(-1, false)]
    public void FreshnessHasAnExactFifteenMinuteLimitAndRejectsFutureEvidence(int ageSeconds, bool expected)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { CheckedAtUtc = Now.AddSeconds(-ageSeconds) } };
        Assert.Equal(expected, UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(UdpRelayStatus.NotVerified)]
    [InlineData(UdpRelayStatus.Unsupported)]
    [InlineData(UdpRelayStatus.Failed)]
    [InlineData((UdpRelayStatus)999)]
    public void OnlyVerifiedStatusCanBeCurrent(UdpRelayStatus status)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { Status = status } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(0, 0, false)]
    [InlineData(2, 2, false)]
    [InlineData(3, 2, false)]
    [InlineData(3, 4, false)]
    [InlineData(3, -1, false)]
    [InlineData(3, 3, true)]
    [InlineData(8, 8, true)]
    [InlineData(9, 9, false)]
    public void CurrentEvidenceRequiresAllPacketsWithinProbeBounds(int sent, int received, bool expected)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { SentPackets = sent, ReceivedPackets = received } };
        Assert.Equal(expected, UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong-profile-fingerprint")]
    public void InvalidEvidenceFingerprintDoesNotBecomeCurrent(string? fingerprint)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { ProfileFingerprint = fingerprint! } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData("0.0.0.0", 30999)]
    [InlineData("::", 30999)]
    [InlineData("echo.example", 30999)]
    [InlineData("http://192.0.2.25", 30999)]
    [InlineData("192.0.2.25", 0)]
    [InlineData("192.0.2.25", 65536)]
    public void MalformedPersistedEndpointCannotBeCurrent(string host, int port)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { TargetHost = host, TargetPort = port } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("192.0.2.25 ")]
    [InlineData("echo.example")]
    [InlineData("0.0.0.0")]
    [InlineData("0.0.0.1")]
    [InlineData("224.0.0.1")]
    [InlineData("239.255.255.250")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("ff02::1")]
    [InlineData("fe80::1")]
    [InlineData("fe80::1%12")]
    [InlineData("2001:db8::25%12")]
    [InlineData("::ffff:0.0.0.0")]
    [InlineData("::ffff:224.0.0.1")]
    [InlineData("::ffff:192.0.2.25%12")]
    public void WildcardMulticastBroadcastScopedAndNonLiteralTargetsAreRejected(string? host)
    {
        Assert.False(UdpVerificationPolicy.IsProbeTarget(host, out _));
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { TargetHost = host! } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData("192.0.2.25", "192.0.2.25")]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::1", "::1")]
    [InlineData("2001:db8::25", "2001:db8::25")]
    [InlineData("::ffff:192.0.2.25", "192.0.2.25")]
    public void LiteralUnicastTargetsAreAcceptedAndMappedAddressesAreNormalized(string host, string expected)
    {
        Assert.True(UdpVerificationPolicy.IsProbeTarget(host, out var address));
        Assert.Equal(expected, address.ToString());
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { TargetHost = host } };
        Assert.True(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(-1d)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void InvalidPersistedRoundTripMetricDoesNotBecomeCurrent(double metric)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { AverageRoundTripMs = metric } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0d)]
    [InlineData(4.5d)]
    public void RoundTripMetricCanBeAbsentOrFiniteAndNonnegative(double? metric)
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { AverageRoundTripMs = metric } };
        Assert.True(UdpVerificationPolicy.IsCurrent(profile, Now));
    }

    [Fact]
    public void NoEvidenceAndNonSocksProfileHaveNoCurrentRelayProof()
    {
        Assert.False(UdpVerificationPolicy.IsCurrent(Profile(), Now));
        Assert.False(UdpVerificationPolicy.IsCurrent(Verified(Profile() with { Protocol = ProxyProtocol.HttpConnect }), Now));
        Assert.False(UdpVerificationPolicy.IsCurrent(Verified(Profile() with { Protocol = ProxyProtocol.HttpsConnect }), Now));
    }

    [Fact]
    public void RelayProofDoesNotRemoveTunUdpRejectionWarning()
    {
        var profile = Verified();
        Assert.True(UdpVerificationPolicy.IsCurrent(profile, Now));
        var compiled = new RuleCompiler().Compile([new RoutingRule
        {
            ProfileId = profile.Id, Network = NetworkTransport.Both
        }], [profile]);
        Assert.True(compiled.IsValid);
        Assert.Contains(compiled.Issues, issue => issue.Code == "udp.unverified" && issue.IsWarning);
        Assert.Equal(FailurePolicy.Block, Assert.Single(compiled.Rules).OnProxyFailure);
    }

    [Fact]
    public void DescriptionsDoNotClaimTransparentRoutingOrVoiceSupport()
    {
        var description = UdpVerificationPolicy.Describe(Verified(), Now);
        Assert.Contains("TUN", description);
        Assert.Contains("Discord voice", description);
        Assert.Contains("не проверены", description);
        Assert.DoesNotContain("opaque-secret-reference", description);
    }

    [Fact]
    public void MaxTimestampEvidenceIsDescribedAsInvalidWithoutClaimingCurrentProof()
    {
        var profile = Verified();
        profile = profile with { UdpVerification = profile.UdpVerification! with { CheckedAtUtc = DateTimeOffset.MaxValue } };
        Assert.False(UdpVerificationPolicy.IsCurrent(profile, Now));
        var description = UdpVerificationPolicy.Describe(profile, Now);
        Assert.Contains("неактуальна", description);
        Assert.Contains("TUN и Discord voice не проверены", description);
        Assert.DoesNotContain("подтверждено", description);
    }

    [Fact]
    public void SchemaOneProfilesRemainReadableWithAndWithoutOptionalEvidence()
    {
        var legacy = JsonSerializer.Deserialize<ProxyProfile>("""{"Id":"6d3fe982-fdee-42a9-9525-edbb35ecbabe","Name":"Old profile","Host":"127.0.0.1","Port":1080}""")!;
        Assert.Null(legacy.UdpVerification);
        var profile = Verified();
        var restored = JsonSerializer.Deserialize<ProxyProfile>(JsonSerializer.Serialize(profile))!;
        Assert.Equal(profile, restored);
        Assert.True(UdpVerificationPolicy.IsCurrent(restored, Now));
    }
}
