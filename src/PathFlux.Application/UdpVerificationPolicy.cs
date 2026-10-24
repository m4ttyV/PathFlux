using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PathFlux.Domain;
namespace PathFlux.Application;

public static class UdpVerificationPolicy
{
    public static readonly TimeSpan Validity = TimeSpan.FromMinutes(15);
    public static string Fingerprint(ProxyProfile profile)
    {
        // No credential value is read or hashed. Replacing credentials changes the opaque reference.
        var identity = JsonSerializer.Serialize(new
        {
            profile.Id, Protocol = (int)profile.Protocol, Host = profile.Host.Trim().ToLowerInvariant(),
            profile.Port, profile.CredentialsRef, TlsServerName = profile.TlsServerName?.Trim().ToLowerInvariant()
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
    }
    public static bool IsCurrent(ProxyProfile profile, DateTimeOffset now)
    {
        var e = profile.UdpVerification;
        return profile.Protocol == ProxyProtocol.Socks5 && e is not null && e.Status == UdpRelayStatus.Verified
            && e.ProfileFingerprint == Fingerprint(profile)
            && e.SentPackets is >= 3 and <= 8 && e.ReceivedPackets == e.SentPackets
            && e.CheckedAtUtc <= now && now - e.CheckedAtUtc <= Validity
            && IsProbeTarget(e.TargetHost, out _)
            && e.TargetPort is >= 1 and <= 65535
            && (e.AverageRoundTripMs is null || double.IsFinite(e.AverageRoundTripMs.Value) && e.AverageRoundTripMs >= 0);
    }
    public static bool IsProbeTarget(string? value, out IPAddress address)
    {
        address = IPAddress.None;
        if (string.IsNullOrWhiteSpace(value) || value != value.Trim() || !IPAddress.TryParse(value, out var parsed)) return false;
        if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.ScopeId != 0) return false;
        if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            var first = parsed.GetAddressBytes()[0];
            if (first == 0 || first >= 224) return false;
        }
        else if (parsed.AddressFamily != AddressFamily.InterNetworkV6 || parsed.Equals(IPAddress.IPv6Any)
            || parsed.IsIPv6Multicast || parsed.IsIPv6LinkLocal || parsed.ScopeId != 0) return false;
        address = parsed;
        return true;
    }
    public static string Describe(ProxyProfile profile, DateTimeOffset now)
    {
        var e = profile.UdpVerification;
        if (e is null) return "Передача UDP через relay не проверялась.";
        if (e.ProfileFingerprint != Fingerprint(profile)) return "Настройки профиля изменились. Повторите UDP echo-проверку.";
        var checkedAt = e.CheckedAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        return e.Status switch
        {
            UdpRelayStatus.Verified when IsCurrent(profile, now) => $"UDP relay: подтверждено {checkedAt}, пакетов {e.ReceivedPackets}/{e.SentPackets}. TUN и Discord voice не проверены.",
            UdpRelayStatus.Verified => $"UDP relay: проверка {checkedAt} неактуальна. Повторите тест. TUN и Discord voice не проверены.",
            UdpRelayStatus.Unsupported => $"Сервер не поддержал UDP ASSOCIATE ({checkedAt}).",
            _ => $"UDP echo не подтверждён ({checkedAt}), ответов {e.ReceivedPackets}/{e.SentPackets}."
        };
    }
}
