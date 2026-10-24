using System.Text.Json.Nodes;
using PathFlux.Domain;
using Xunit;
namespace PathFlux.Engine.Tests;

public static class EngineTestBinary
{
    // The helper/CI obtains this hash only after verifying the official release archive.
    // Retain the old 1.12.12 fixture default for previously documented test commands only.
    public static string ExpectedHash => Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE_SHA256") ?? "f1e6453b62482a95c9461d2c84d8e1a95567609f739adf6a1227a9b96c578747";
}

public sealed class EngineVersionTests
{
    [Theory]
    [InlineData("1.12.2", "1.12.2")]
    [InlineData("1.12.12", "1.12.12")]
    [InlineData("1.13.21", "1.13.21")]
    [InlineData("1.14.3", "1.14.3")]
    [InlineData("1.15.0-alpha.12", "1.15.0")]
    [InlineData("1.12.2+build.1", "1.12.2")]
    [InlineData("2.0.0", "2.0.0")]
    public void AcceptsMinimumAndNewerSemver(string text, string expected)
        => Assert.Equal(Version.Parse(expected), EngineBinary.ParseVersion($"sing-box version {text}\r\nEnvironment: go1.25 windows/amd64\r\n"));

    [Theory]
    [InlineData("1.12.1")]
    [InlineData("1.11.15")]
    [InlineData("1.12.2-rc.1")]
    [InlineData("1.12")]
    [InlineData("1.12.2.1")]
    [InlineData("01.12.2")]
    [InlineData("999999999999.12.2")]
    [InlineData("1.14.3 garbage")]
    public void RejectsOldPrereleaseMinimumAndMalformedVersions(string text)
        => Assert.Throws<InvalidOperationException>(() => EngineBinary.ParseVersion("sing-box version " + text));

    [Fact]
    public void DoesNotSearchForVersionInArbitraryOutput()
        => Assert.Throws<InvalidOperationException>(() => EngineBinary.ParseVersion("another binary\nsing-box version 1.14.3"));

    [Theory]
    [InlineData(12, true)]
    [InlineData(14, true)]
    [InlineData(15, false)]
    [InlineData(17, false)]
    public async Task NewTunStackOmitsRemovedStackOption(int minor, bool legacyStack)
    {
        var json = JsonNode.Parse(await new SingBoxConfigGenerator(new NoSecrets()).GenerateAsync(new(), default, engineVersion: new Version(1, minor, 2)))!;
        Assert.Equal(legacyStack, json["inbounds"]![0]!["stack"] is not null);
    }

    [Fact]
    public async Task InvalidOrMismatchedHashRejectsFileBeforeAnyExecution()
    {
        var directory = Path.Combine(Path.GetTempPath(), "PathFlux-hash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "sing-box.exe");
        await File.WriteAllTextAsync(path, "This is deliberately not an executable.");
        try
        {
            foreach (var hash in new[] { "", "xyz", new string('g', 64), new string('0', 64) })
            {
                var error = await Assert.ThrowsAsync<InvalidOperationException>(() => EngineBinary.VerifyAsync(path, hash, default));
                Assert.True(error.Message.Contains("SHA-256") || error.Message.Contains("Контрольная сумма"));
            }
        }
        finally { File.Delete(path); Directory.Delete(directory); }
    }

    [EngineFact]
    public async Task ActualVersionAndConfiguredHashAreValidatedByUiAdapter()
    {
        var path = Environment.GetEnvironmentVariable("PATHFLUX_TEST_ENGINE")!;
        var version = await EngineBinary.VerifyAsync(path, EngineTestBinary.ExpectedHash.ToUpperInvariant(), default);
        Assert.True(version >= EngineBinary.MinimumVersion);
        await using var adapter = new SingBoxEngineAdapter(new NoSecrets());
        var result = await adapter.ValidateAsync(new() { Settings = new() { EnginePath = path, EngineSha256 = EngineTestBinary.ExpectedHash } }, default);
        Assert.True(result.IsValid, string.Join("; ", result.Issues.Select(i => i.Message)));
    }

    private sealed class NoSecrets : PathFlux.Application.ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
