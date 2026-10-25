using System.Net;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class DockerUdpRelayAudit
{
    public static async Task<int> RunAsync(string output, CancellationToken ct, bool automatic = false)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Scope = (automatic ? "Automatic Docker port discovery. " : "Manual Docker ports. ") + "Real Docker UDP DNS via strict bridge, no engine or TUN; does not accept transparent DNS/TUN or Discord" };
        try
        {
            report.Before = await NetworkSnapshot.CaptureAsync(ct);
            if (automatic)
            {
                var result = await new PathFlux.Infrastructure.ProxyDiagnostics(new NoSecrets(), TimeSpan.FromSeconds(10)).TestUdpConnectivityAsync(
                    new() { Host = "127.0.0.1", Port = 1080, UdpRelayMode = PathFlux.Domain.UdpRelayMode.Auto }, ct);
                report.Cases.Add(new("DockerOneClickUdpConnectivity", result.Success, result.Success, true, false, new()));
                if (!result.Success) throw new InvalidOperationException("DockerOneClickUdpNotVerified");
            }
            var binding = automatic ? new UdpRelayBinding(AutomaticProfile: new() { Host = "127.0.0.1", Port = 1080, UdpRelayMode = PathFlux.Domain.UdpRelayMode.Auto }) : new(20000, 20030);
            await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, 1080), binding);
            for (int i = 0; i < 3; i++)
            {
                var result = await UdpProbe.DnsThroughBridgeAsync(bridge, ct);
                report.Cases.Add(new("DockerUdpDnsRelay" + i, result.Success, result.Success, true, false,
                    new() { ["Sent"] = checked((int)bridge.SentPackets), ["Received"] = checked((int)bridge.ReceivedPackets),
                        ["AdvertisedPort"] = bridge.LastAdvertisedRelay?.Port ?? 0, ["EffectivePort"] = bridge.LastEffectiveRelay?.Port ?? 0 }));
                if (!result.Success) throw new InvalidOperationException("DockerUdpDnsReplyNotVerified");
            }
            report.Status = automatic ? "PassedDockerUdpAutoDnsRelayOnly_NoTun" : "PassedDockerUdpDnsRelayOnly_NoTun";
        }
        catch (Exception ex) { report.Status = "Failed"; report.ErrorCode = ex is InvalidOperationException ? ex.Message : ex.GetType().Name; }
        finally
        {
            report.After = await NetworkSnapshot.CaptureAsync(CancellationToken.None);
            bool same = report.Before?.CompareRecovery(report.After).Length == 0;
            for (int i = 0; i < report.Cases.Count; i++) report.Cases[i] = report.Cases[i] with { RecoveryConfirmed = same, Passed = report.Cases[i].Passed && same };
            if (!same) report.Status = "RecoveryNotConfirmed";
            await report.SaveAsync(output); Console.WriteLine(report.Status);
        }
        return report.Status == (automatic ? "PassedDockerUdpAutoDnsRelayOnly_NoTun" : "PassedDockerUdpDnsRelayOnly_NoTun") ? 0 : 1;
    }
    private sealed class NoSecrets : PathFlux.Application.ISecretStore
    {
        public Task<PathFlux.Domain.ProxyCredentials?> GetAsync(string reference, CancellationToken ct) => Task.FromResult<PathFlux.Domain.ProxyCredentials?>(null);
        public Task<string> StoreAsync(PathFlux.Domain.ProxyCredentials credentials, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(string reference, CancellationToken ct) => throw new NotSupportedException();
    }
}
