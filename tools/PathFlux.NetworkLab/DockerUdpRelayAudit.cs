using System.Net;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class DockerUdpRelayAudit
{
    public static async Task<int> RunAsync(string output, CancellationToken ct)
    {
        Directory.CreateDirectory(output);
        var report = new LabReport { Scope = "Real Docker UDP DNS via strict bridge, no engine or TUN; does not accept transparent DNS/TUN or Discord" };
        try
        {
            report.Before = await NetworkSnapshot.CaptureAsync(ct);
            await using var bridge = new StrictSocksUdpBridge(new(IPAddress.Loopback, 1080), new(20000, 20030));
            for (int i = 0; i < 3; i++)
            {
                var result = await UdpProbe.DnsThroughBridgeAsync(bridge, ct);
                report.Cases.Add(new("DockerUdpDnsRelay" + i, result.Success, result.Success, true, false,
                    new() { ["Sent"] = bridge.SentPackets, ["Received"] = bridge.ReceivedPackets,
                        ["AdvertisedPort"] = bridge.LastAdvertisedRelay?.Port ?? 0, ["EffectivePort"] = bridge.LastEffectiveRelay?.Port ?? 0 }));
                if (!result.Success) throw new InvalidOperationException("DockerUdpDnsReplyNotVerified");
            }
            report.Status = "PassedDockerUdpDnsRelayOnly_NoTun";
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
        return report.Status == "PassedDockerUdpDnsRelayOnly_NoTun" ? 0 : 1;
    }
}
