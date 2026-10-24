using System.Text.Json;
using PathFlux.Domain;
using Xunit;

namespace PathFlux.Infrastructure.Tests;

public class UdpSchemaMigrationTests
{
    [Fact]
    public async Task MigrationPreservesRulesAndSecretsButAlwaysDisablesLegacyUdp()
    {
        string path = Path.Combine(Path.GetTempPath(), "PathFlux-migration-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var id = Guid.NewGuid();
            await File.WriteAllTextAsync(path, """{"schemaVersion":1,"profiles":[{"id":"PROFILE_ID","credentialsRef":"opaque-secret","udpRelayMode":"dockerNat","udpPublishedPortFirst":20000,"udpPublishedPortLast":20030}],"rules":[{"profileId":"PROFILE_ID","network":"both"}],"settings":{"experimentalSocksUdp":true}}""".Replace("PROFILE_ID", id.ToString()));
            var store = new JsonConfigurationStore(path); var config = await store.LoadAsync(default);
            Assert.Equal(2, config.SchemaVersion); Assert.False(config.Settings.ExperimentalSocksUdp);
            Assert.Equal("opaque-secret", config.Profiles.Single().CredentialsRef); Assert.Equal(id, config.Rules.Single().ProfileId);
            Assert.Equal(UdpRelayMode.Standard, config.Profiles.Single().UdpRelayMode);
            var original = await File.ReadAllTextAsync(path); Assert.Contains("\"schemaVersion\":1", original);
            await store.SaveAsync(config with { Settings = config.Settings with { ExperimentalSocksUdp = true } }, default);
            Assert.True((await store.LoadAsync(default)).Settings.ExperimentalSocksUdp);
            Assert.Equal(original, await File.ReadAllTextAsync(path + ".bak"));
        }
        finally { File.Delete(path); File.Delete(path + ".bak"); }
    }
}
