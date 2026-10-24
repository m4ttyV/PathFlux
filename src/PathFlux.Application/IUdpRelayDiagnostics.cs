using PathFlux.Domain;
namespace PathFlux.Application;

public interface IUdpRelayDiagnostics
{
    Task<UdpRelayProbeResult> TestUdpRelayAsync(ProxyProfile profile, UdpProbeOptions options, CancellationToken ct);
}
