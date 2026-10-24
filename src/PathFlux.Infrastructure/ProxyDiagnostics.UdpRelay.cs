using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

public sealed partial class ProxyDiagnostics
{
    // RFC 1928 sections 6–7: an association is tied to its TCP control connection.
    // This tests the upstream relay only and never enables transparent TUN UDP routing.
    public async Task<UdpRelayProbeResult> TestUdpRelayAsync(ProxyProfile profile, UdpProbeOptions options, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(options);
        ct.ThrowIfCancellationRequested();
        var fingerprint = UdpVerificationPolicy.Fingerprint(profile);
        var sent = 0;
        var received = 0;
        double elapsedMilliseconds = 0;
        var targetText = options.TargetHost;
        var stage = "validation";
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_timeout);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        Task<int>? control = null;
        Task<UdpReceiveResult>? pendingReceive = null;
        UdpRelayProbeResult Result(UdpRelayStatus status, string message) => new(status == UdpRelayStatus.Verified, stage, message,
            new(fingerprint, DateTimeOffset.UtcNow, status, targetText, options.TargetPort, sent, received,
                received == 0 ? null : elapsedMilliseconds / received));
        try
        {
            if (profile.Protocol != ProxyProtocol.Socks5)
                return Result(UdpRelayStatus.Unsupported, "Этот протокол не поддерживает SOCKS5 UDP relay.");
            if (!ConfigurationValidator.ValidatePolicy([], [profile]).IsValid)
                throw new ProbeException("validation", "Некорректны параметры профиля или диапазон опубликованных UDP-портов.");
            if (!UdpVerificationPolicy.IsProbeTarget(options.TargetHost, out var target) ||
                options.TargetPort is < 1 or > 65535 || options.PacketCount is < 3 or > 8)
                throw new ProbeException("validation", "Укажите допустимый IP echo-сервера, порт 1–65535 и от 3 до 8 пакетов. DNS-имена, multicast, broadcast и scoped IPv6 не поддерживаются.");
            targetText = target.ToString();
            var proxyHost = ExperimentalUdpPolicy.IsDockerHost(profile.Host) ? "127.0.0.1" : NormalizeHost(profile.Host);
            if (profile.Port is < 1 or > 65535)
                throw new ProbeException("validation", "Некорректный порт прокси.");
            ProxyCredentials? credentials = null;
            if (profile.CredentialsRef is not null)
            {
                stage = "credentials";
                credentials = await secrets.GetAsync(profile.CredentialsRef, lifetime.Token).ConfigureAwait(false)
                    ?? throw new ProbeException(stage, "Сохранённые учётные данные не найдены.");
            }
            stage = "tcp";
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(proxyHost, profile.Port, lifetime.Token).ConfigureAwait(false);
            var local = (IPEndPoint)tcp.Client.LocalEndPoint!;
            var remote = (IPEndPoint)tcp.Client.RemoteEndPoint!;
            if (local.Address.IsIPv4MappedToIPv6) local = new(local.Address.MapToIPv4(), local.Port);
            if (remote.Address.IsIPv4MappedToIPv6) remote = new(remote.Address.MapToIPv4(), remote.Port);
            using var udp = new UdpClient(local.AddressFamily);
            // Bind before ASSOCIATE, and advertise the real socket endpoint, not the echo target.
            udp.Client.Bind(new IPEndPoint(local.Address, 0));
            var udpLocal = (IPEndPoint)udp.Client.LocalEndPoint!;
            var stream = tcp.GetStream();
            stage = "authentication";
            await AuthenticateSocksAsync(stream, credentials, lifetime.Token).ConfigureAwait(false);
            stage = "udp-associate";
            var relay = await AssociateRelayAsync(stream, profile.UdpRelayMode == UdpRelayMode.DockerNat ? new(IPAddress.Any, 0) : udpLocal,
                remote.Address, profile, lifetime.Token).ConfigureAwait(false);
            if (relay.AddressFamily != udpLocal.AddressFamily)
                throw new ProbeException(stage, "Семейство адреса UDP relay несовместимо с TCP-ассоциацией.");
            udp.Connect(relay);
            control = stream.ReadAsync(new byte[1], lifetime.Token).AsTask();
            stage = "udp-relay";
            var probes = new List<PendingUdpProbe>(options.PacketCount);
            for (var index = 0; index < options.PacketCount; index++)
            {
                await EnsureControlOpenAsync(control, tcp.Client).ConfigureAwait(false);
                var payload = RandomNumberGenerator.GetBytes(64);
                var packet = EncodeUdpPacket(target, options.TargetPort, payload);
                var started = Stopwatch.GetTimestamp();
                var count = await udp.SendAsync(packet, lifetime.Token).ConfigureAwait(false);
                if (count != packet.Length) throw new ProbeException(stage, "UDP-пакет отправлен не полностью.");
                probes.Add(new(payload, started));
                sent++;
            }
            while (received < probes.Count)
            {
                pendingReceive = udp.ReceiveAsync(lifetime.Token).AsTask();
                await Task.WhenAny(pendingReceive, control).ConfigureAwait(false);
                await EnsureControlOpenAsync(control, tcp.Client).ConfigureAwait(false);
                var datagram = await pendingReceive.ConfigureAwait(false);
                pendingReceive = null;
                // UdpClient.Connect additionally filters the outer source IP and port in the OS.
                if (!datagram.RemoteEndPoint.Equals(relay)) continue;
                if (!TryGetEchoPayload(datagram.Buffer, target, options.TargetPort, out var payload)) continue;
                var probe = probes.FirstOrDefault(p => !p.Received && payload.Span.SequenceEqual(p.Payload));
                if (probe is null) continue; // Ignore duplicates, stale nonces, and unrelated packets.
                probe.Received = true;
                received++;
                elapsedMilliseconds += Stopwatch.GetElapsedTime(probe.Started).TotalMilliseconds;
            }
            // Observe an EOF/FIN that raced the last UDP reply before issuing historical proof.
            await Task.Yield();
            await EnsureControlOpenAsync(control, tcp.Client).ConfigureAwait(false);
            return Result(UdpRelayStatus.Verified, "UDP relay передал все случайные echo-пакеты. Прозрачная маршрутизация TUN и Discord voice этим тестом не проверяются.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return Result(UdpRelayStatus.Failed, "Истекло время ожидания UDP echo. Передача UDP не подтверждена."); }
        catch (ProbeException exception)
        {
            stage = exception.Stage;
            return Result(exception.UdpStatus == SupportStatus.Unsupported ? UdpRelayStatus.Unsupported : UdpRelayStatus.Failed, exception.SafeMessage);
        }
        catch (SocketException)
        { return Result(UdpRelayStatus.Failed, "Сетевое соединение с прокси или UDP relay недоступно."); }
        catch (IOException)
        { return Result(UdpRelayStatus.Failed, "Управляющее соединение закрыто или SOCKS5-ответ неполный."); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or UnauthorizedAccessException or NotSupportedException)
        { return Result(UdpRelayStatus.Failed, "Параметры проверки или защищённые учётные данные недоступны."); }
        finally
        {
            lifetime.Cancel();
            await ObserveProbeEndAsync(pendingReceive).ConfigureAwait(false);
            await ObserveProbeEndAsync(control).ConfigureAwait(false);
        }
    }

    private static async Task<IPEndPoint> AssociateRelayAsync(Stream stream, IPEndPoint local, IPAddress tcpRemote, ProxyProfile profile, CancellationToken ct)
    {
        var address = local.Address.GetAddressBytes();
        var request = new byte[address.Length + 6];
        request[0] = 5;
        request[1] = 3;
        request[3] = local.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
        address.CopyTo(request, 4);
        request[^2] = (byte)(local.Port >> 8);
        request[^1] = (byte)local.Port;
        await stream.WriteAsync(request, ct).ConfigureAwait(false);
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        if (header[0] != 5 || header[2] != 0) throw new ProbeException("udp-associate", "Некорректный ответ UDP ASSOCIATE.");
        if (header[1] != 0)
            throw new ProbeException("udp-associate", SocksFailure(header[1]), header[1] == 7 ? SupportStatus.Unsupported : null);
        IPAddress relayAddress;
        if (header[3] is 1 or 4)
        {
            var bytes = new byte[header[3] == 1 ? 4 : 16];
            await stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
            relayAddress = new IPAddress(bytes);
        }
        else if (header[3] == 3)
        {
            var length = await ReadDomainLengthAsync(stream, ct).ConfigureAwait(false);
            var bytes = new byte[length];
            await stream.ReadExactlyAsync(bytes, ct).ConfigureAwait(false);
            if (bytes.Any(b => b is > 127 or < 33)) throw new ProbeException("udp-associate", "Некорректное DNS-имя UDP relay.");
            var domain = NormalizeHost(Encoding.ASCII.GetString(bytes));
            using var lookup = CancellationTokenSource.CreateLinkedTokenSource(ct);
            lookup.CancelAfter(TimeSpan.FromSeconds(3));
            var candidates = await Dns.GetHostAddressesAsync(domain, lookup.Token).ConfigureAwait(false);
            relayAddress = candidates.FirstOrDefault(ip => ip.AddressFamily == local.AddressFamily &&
                UdpVerificationPolicy.IsProbeTarget(ip.ToString(), out _))
                ?? throw new ProbeException("udp-associate", "DNS-имя UDP relay не разрешилось в совместимый адрес.");
        }
        else throw new ProbeException("udp-associate", "Неизвестный тип адреса UDP relay.");
        var port = new byte[2];
        await stream.ReadExactlyAsync(port, ct).ConfigureAwait(false);
        var relayPort = (port[0] << 8) | port[1];
        if (relayPort == 0) throw new ProbeException("udp-associate", "Прокси вернул нулевой порт UDP relay.");
        if (profile.UdpRelayMode == UdpRelayMode.DockerNat)
        {
            if (!tcpRemote.Equals(IPAddress.Loopback) || relayPort < profile.UdpPublishedPortFirst || relayPort > profile.UdpPublishedPortLast)
                throw new ProbeException("udp-associate", "UDP-порт релея не входит в явный диапазон Docker NAT или прокси не является IPv4 loopback.");
            relayAddress = tcpRemote;
        }
        if (relayAddress.IsIPv4MappedToIPv6) relayAddress = relayAddress.MapToIPv4();
        if (relayAddress.Equals(IPAddress.Any) || relayAddress.Equals(IPAddress.IPv6Any)) relayAddress = tcpRemote;
        if (!UdpVerificationPolicy.IsProbeTarget(relayAddress.ToString(), out relayAddress))
            throw new ProbeException("udp-associate", "Прокси вернул недопустимый адрес UDP relay.");
        return new(relayAddress, relayPort);
    }

    private static byte[] EncodeUdpPacket(IPAddress target, int port, byte[] payload)
    {
        var address = target.GetAddressBytes();
        var packet = new byte[address.Length + 6 + payload.Length];
        packet[3] = target.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
        address.CopyTo(packet, 4);
        packet[address.Length + 4] = (byte)(port >> 8);
        packet[address.Length + 5] = (byte)port;
        payload.CopyTo(packet, address.Length + 6);
        return packet;
    }

    private static bool TryGetEchoPayload(byte[] packet, IPAddress target, int port, out ReadOnlyMemory<byte> payload)
    {
        payload = default;
        if (packet.Length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) return false;
        var addressLength = packet[3] switch { 1 => 4, 4 => 16, _ => 0 };
        if (addressLength == 0 || packet.Length < addressLength + 6) return false;
        var address = new IPAddress(packet.AsSpan(4, addressLength));
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (!address.Equals(target) || ((packet[addressLength + 4] << 8) | packet[addressLength + 5]) != port) return false;
        payload = packet.AsMemory(addressLength + 6);
        return true;
    }

    private static async Task EnsureControlOpenAsync(Task<int> control, Socket socket)
    {
        if (control.IsCompleted)
        {
            await control.ConfigureAwait(false);
            throw new ProbeException("udp-control", "Управляющее TCP-соединение закрыто или содержит неожиданные данные. UDP-ассоциация недействительна.");
        }
        if (socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0)
            throw new ProbeException("udp-control", "Управляющее TCP-соединение закрыто. UDP-ассоциация недействительна.");
    }

    private static async Task ObserveProbeEndAsync(Task? task)
    {
        if (task is null) return;
        try { await task.ConfigureAwait(false); }
        catch (Exception exception) when (exception is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
    }

    private sealed class PendingUdpProbe(byte[] payload, long started)
    {
        public byte[] Payload { get; } = payload;
        public long Started { get; } = started;
        public bool Received { get; set; }
    }
}
