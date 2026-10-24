namespace PathFlux.Domain;

public enum UdpRelayStatus { NotVerified, Verified, Unsupported, Failed }

/// <summary>A user-selected IP echo endpoint. A reply must contain the exact unpredictable payload.</summary>
public sealed record UdpProbeOptions(string TargetHost, int TargetPort, int PacketCount = 3);

/// <summary>Historical relay proof only; this never asserts transparent TUN routing or Discord voice.</summary>
public sealed record UdpProbeEvidence(
    string ProfileFingerprint, DateTimeOffset CheckedAtUtc, UdpRelayStatus Status,
    string TargetHost, int TargetPort, int SentPackets, int ReceivedPackets,
    double? AverageRoundTripMs = null);

public sealed record UdpRelayProbeResult(bool Success, string Stage, string Message, UdpProbeEvidence Evidence);
