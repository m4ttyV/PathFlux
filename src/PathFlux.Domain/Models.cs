namespace PathFlux.Domain;

public enum ProxyProtocol { Socks5, HttpConnect, HttpsConnect }
public enum UdpRelayMode { Standard, DockerNat, Auto }
public enum SelectorKind { ProcessName, ExecutablePath, ProcessInstance }
public enum NetworkTransport { Tcp, Udp, Both }
public enum RouteAction { Direct, Block, Proxy }
public enum FailurePolicy { Block, Direct }
public enum RuleLifetime { Persistent, UntilProcessExit }
public enum SupportStatus { Implemented, Partial, Unsupported, NotVerified, Failed, Experimental }
public enum EngineState { Stopped, Starting, Running, Degraded, Stopping, Failed }

public sealed record ProxyProfile
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; init; } = "Новый прокси";
    public bool Enabled { get; init; } = true;
    public ProxyProtocol Protocol { get; init; }
    public string Host { get; init; } = "127.0.0.1";
    public int Port { get; init; } = 1080;
    public string? CredentialsRef { get; init; }
    public string? TlsServerName { get; init; }
    public UdpProbeEvidence? UdpVerification { get; init; }
    public UdpRelayMode UdpRelayMode { get; init; }
    public bool UseTlsServerNameForTcp { get; init; }
    public string TcpIpv4DohServer { get; init; } = "https://1.1.1.1/dns-query";
    public int? UdpPublishedPortFirst { get; init; }
    public int? UdpPublishedPortLast { get; init; }
    public override string ToString() => Name;
}
public sealed record ProcessInstanceId(int Pid, DateTimeOffset StartTimeUtc, ulong? SequenceNumber = null);
public sealed record ProcessSelector(SelectorKind Kind, string Value, ProcessInstanceId? Instance = null);
public sealed record RoutingRule
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public string Name { get; init; } = "Новое правило";
    public bool Enabled { get; init; } = true;
    public int Priority { get; init; } = 100;
    public ProcessSelector Selector { get; init; } = new(SelectorKind.ProcessName, "Discord.exe");
    public bool IncludeChildren { get; init; }
    public NetworkTransport Network { get; init; } = NetworkTransport.Both;
    public RouteAction Action { get; init; } = RouteAction.Proxy;
    public Guid? ProfileId { get; init; }
    public FailurePolicy OnProxyFailure { get; init; } = FailurePolicy.Block;
    public RuleLifetime Lifetime { get; init; } = RuleLifetime.Persistent;
}
public sealed record AppSettings
{
    public string EnginePath { get; init; } = "";
    public string EngineSha256 { get; init; } = "";
    public string Theme { get; init; } = "Dark";
    public string Language { get; init; } = "ru";
    public int ProcessRefreshSeconds { get; init; } = 5;
    public bool BypassLan { get; init; }
    public string DnsMode { get; init; } = "System";
    public bool ExperimentalSocksUdp { get; init; }
    public bool ExperimentalProcessTrees { get; init; }
}
public sealed record ProxyConfiguration
{
    public int SchemaVersion { get; init; } = 2;
    public RouteAction DefaultAction { get; init; } = RouteAction.Direct;
    public List<ProxyProfile> Profiles { get; init; } = [];
    public List<RoutingRule> Rules { get; init; } = [];
    public AppSettings Settings { get; init; } = new();
}
public sealed record ProxyCredentials(string Username, string Password);
public sealed record ProcessInfo(int Pid, string Name, string? ExecutablePath, DateTimeOffset? StartTimeUtc, int? ParentPid = null, ulong? SequenceNumber = null)
{
    public string PathDisplay => ExecutablePath ?? "Нет доступа";
}
public sealed record EngineCapabilities(
    SupportStatus ProcessName, SupportStatus ExecutablePath, SupportStatus ExactPid,
    SupportStatus Children, SupportStatus Tcp, SupportStatus Udp, SupportStatus KillSwitch);
public sealed record UdpBridgeStatistics(Guid ProfileId, string State, int ActiveAssociations, long SentPackets, long ReceivedPackets,
    long Reconnects, long DroppedFragments, long DroppedInvalid, string? LastError);
public sealed record EngineStatus(EngineState State, string Message, int? ProcessId = null, IReadOnlyList<UdpBridgeStatistics>? Udp = null);
public sealed record ValidationIssue(string Code, string Message, Guid? RuleId = null, bool IsWarning = false);
public sealed record ConfigValidationResult(IReadOnlyList<ValidationIssue> Issues)
{
    public bool IsValid => Issues.All(i => i.IsWarning);
    public static ConfigValidationResult Success { get; } = new([]);
}
public sealed record CompiledPolicy(IReadOnlyList<RoutingRule> Rules, IReadOnlyList<ProxyProfile> Profiles, IReadOnlyList<ValidationIssue> Issues)
{
    public bool IsValid => Issues.All(i => i.IsWarning);
}
public sealed record AttributionCapabilities(bool ExactPid, bool Children, string Reason);
public sealed record NetworkStateRecoveryMetadata(int SchemaVersion, int AgentPid, DateTimeOffset StartedUtc, string InterfaceName, string State);
public sealed record ConnectionEvent(DateTimeOffset TimestampUtc, string Component, string Code, string Message, Guid? RuleId = null, Guid? ProfileId = null);
public sealed record DiagnosticResult(bool Success, string Stage, string Message, SupportStatus Udp = SupportStatus.NotVerified);
