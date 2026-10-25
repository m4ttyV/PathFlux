using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

public sealed partial class ProxyDiagnostics
{
    // Explicit user action: one nonce-tagged DNS transaction, exclusively inside SOCKS UDP.
    // No user browsing names, no system DNS reconfiguration and no direct retry.
    public async Task<DiagnosticResult> TestUdpConnectivityAsync(ProxyProfile profile, CancellationToken ct)
    {
        if (profile.Protocol != ProxyProtocol.Socks5)
            return new(false, "udp", "UDP требует SOCKS5. HTTP/HTTPS CONNECT его не поддерживают.", SupportStatus.Unsupported);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lifetime.CancelAfter(_timeout);
        var token = lifetime.Token;
        Task<int>? control = null;
        Task<UdpReceiveResult>? receive = null;
        try
        {
            if (!ConfigurationValidator.ValidatePolicy([], [profile]).IsValid)
                return new(false, "udp", "Проверьте настройки SOCKS5 и ручной диапазон UDP-портов.");
            var credentials = profile.CredentialsRef is { } reference ? await secrets.GetAsync(reference, token)
                ?? throw new ProbeException("credentials", "Не найдены сохранённые учётные данные.") : null;
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(ExperimentalUdpPolicy.IsDockerHost(profile.Host) ? "127.0.0.1" : NormalizeHost(profile.Host), profile.Port, token);
            var local = (IPEndPoint)tcp.Client.LocalEndPoint!;
            var peer = (IPEndPoint)tcp.Client.RemoteEndPoint!;
            if (local.Address.IsIPv4MappedToIPv6) local = new(local.Address.MapToIPv4(), local.Port);
            if (peer.Address.IsIPv4MappedToIPv6) peer = new(peer.Address.MapToIPv4(), peer.Port);
            using var udp = new UdpClient(local.AddressFamily);
            udp.Client.Bind(new IPEndPoint(local.Address, 0));
            var stream = tcp.GetStream();
            await AuthenticateSocksAsync(stream, credentials, token);
            var relay = await AssociateRelayAsync(stream, profile.UdpRelayMode is UdpRelayMode.Auto or UdpRelayMode.DockerNat ? new(IPAddress.Any, 0) : (IPEndPoint)udp.Client.LocalEndPoint!, peer.Address, profile, token);
            if (relay.AddressFamily != local.AddressFamily) throw new ProbeException("udp", "Семейство адресов UDP-релея несовместимо с подключением.");
            udp.Connect(relay);
            control = stream.ReadAsync(new byte[1], token).AsTask();
            var question = Encoding.ASCII.GetBytes("pathflux-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant());
            byte[] query = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, (byte)question.Length, .. question, 7, .. Encoding.ASCII.GetBytes("example"), 3, .. Encoding.ASCII.GetBytes("com"), 0, 0, 1, 0, 1];
            RandomNumberGenerator.Fill(query.AsSpan(0, 2));
            var target = IPAddress.Parse("1.1.1.1");
            await EnsureControlOpenAsync(control, tcp.Client);
            await udp.SendAsync(EncodeUdpPacket(target, 53, query), token);
            for (int invalid = 0; invalid < 32; invalid++)
            {
                receive = udp.ReceiveAsync(token).AsTask();
                await Task.WhenAny(receive, control);
                await EnsureControlOpenAsync(control, tcp.Client);
                var packet = await receive;
                if (!TryGetEchoPayload(packet.Buffer, target, 53, out var payload)) continue;
                var reply = payload.Span;
                if (reply.Length < query.Length || reply[0] != query[0] || reply[1] != query[1] ||
                    (reply[2] & 0xFA) != 0x80 || reply[4] != 0 || reply[5] != 1 || !reply.Slice(12, query.Length - 12).SequenceEqual(query.AsSpan(12))) continue;
                return new(true, "udp-relay", "UDP работает через этот прокси: получен проверенный DNS-ответ. Маршрутизация приложения через TUN проверяется отдельно.", SupportStatus.Partial);
            }
            return new(false, "udp-relay", "Релей прислал некорректные UDP-ответы. Проверка не пройдена.");
        }
        catch (ProbeException ex) { return new(false, ex.Stage, ex.SafeMessage, ex.UdpStatus ?? SupportStatus.NotVerified); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return new(false, "udp-relay", "Ответ UDP не получен за отведённое время. Прокси, релей или проверочный DNS-сервер недоступен; прямой обход не использовался."); }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException)
        { return new(false, "udp-relay", "Не удалось передать UDP через прокси. Проверьте доступность сервера, авторизацию и публикацию UDP-портов."); }
        finally
        {
            await lifetime.CancelAsync();
            await ObserveProbeEndAsync(receive);
            await ObserveProbeEndAsync(control);
        }
    }
}
