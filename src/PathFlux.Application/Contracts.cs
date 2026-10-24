using PathFlux.Domain;
namespace PathFlux.Application;

public interface IProxyEngineAdapter
{
    Task<EngineCapabilities> GetCapabilitiesAsync(CancellationToken ct);
    Task<ConfigValidationResult> ValidateAsync(ProxyConfiguration config, CancellationToken ct);
    Task StartAsync(ProxyConfiguration config, CancellationToken ct);
    Task StopAsync(CancellationToken ct);
    Task<EngineStatus> GetStatusAsync(CancellationToken ct);
}
public interface IProcessDiscoveryService
{
    Task<IReadOnlyList<ProcessInfo>> GetProcessesAsync(CancellationToken ct);
}
public interface IRuleCompiler
{
    Task<CompiledPolicy> CompileAsync(IReadOnlyList<RoutingRule> rules, IReadOnlyList<ProxyProfile> profiles, CancellationToken ct);
}
public interface IConnectionAttributionProvider
{
    Task<AttributionCapabilities> GetCapabilitiesAsync(CancellationToken ct);
}
public interface IConfigurationStore
{
    Task<ProxyConfiguration> LoadAsync(CancellationToken ct);
    Task SaveAsync(ProxyConfiguration configuration, CancellationToken ct);
}
public interface ISecretStore
{
    Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct);
    Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct);
    Task DeleteAsync(string reference, CancellationToken ct);
}
public interface IProxyDiagnostics
{
    Task<DiagnosticResult> TestTcpAsync(ProxyProfile profile, string targetHost, int targetPort, CancellationToken ct);
    Task<DiagnosticResult> TestUdpAssociateAsync(ProxyProfile profile, CancellationToken ct);
}
