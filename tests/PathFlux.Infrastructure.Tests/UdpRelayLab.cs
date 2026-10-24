using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PathFlux.Domain;

// Shared integration harness: this file has no dependency on xUnit and can be linked into other test projects.
namespace PathFlux.Testing;

public sealed class UdpEchoServer : IAsyncDisposable
{
    private readonly UdpClient _socket;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;
    private int _received;
    public IPEndPoint EndPoint => (IPEndPoint)_socket.Client.LocalEndPoint!;
    public int ReceivedPackets => Volatile.Read(ref _received);
    public ConcurrentQueue<byte[]> Payloads { get; } = new();

    public UdpEchoServer(AddressFamily family = AddressFamily.InterNetwork)
    {
        _socket = new UdpClient(new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback, 0));
        _loop = Task.Run(async () =>
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var packet = await _socket.ReceiveAsync(_stop.Token);
                    Interlocked.Increment(ref _received);
                    Payloads.Enqueue(packet.Buffer.ToArray());
                    await _socket.SendAsync(packet.Buffer, packet.RemoteEndPoint, _stop.Token);
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
        });
    }
    public async ValueTask DisposeAsync()
    {
        _stop.Cancel(); _socket.Dispose();
        try { await _loop; } finally { _stop.Dispose(); }
    }
}

public enum UdpRelayAddressMode { Literal, Wildcard, Domain }
public enum UdpRelayFault
{
    None, DropResponses, WrongPayload, WrongTargetAddress, WrongTargetPort, NonzeroReserved,
    Fragmented, Truncated, DomainTarget, WrongAddressType, WrongPayloadLength, StaleThenValid, WrongOuterSource,
    CloseControlBeforeRelay, CloseControlBeforeLastReply
}
public sealed record Socks5UdpRelayOptions
{
    public IPEndPoint? TargetOverride { get; init; }
    public IPAddress? AdvertisedAddress { get; init; }
    public byte FragmentValue { get; init; } = 1;
    public int FaultAssociations { get; init; } = int.MaxValue;
    public int DropEveryNthReply { get; init; }
    public TimeSpan SessionLifetime { get; init; } = TimeSpan.FromSeconds(30);
    public ProxyCredentials? Credentials { get; init; }
    public byte ReplyCode { get; init; }
    public bool ZeroRelayPort { get; init; }
    public UdpRelayAddressMode AddressMode { get; init; }
    public UdpRelayFault Fault { get; init; }
    public int CloseAfterPackets { get; init; } = 3;
    public bool FragmentTcpReplies { get; init; }
}

/// <summary>A local test SOCKS5 relay that forwards decoded payloads to an independent UDP echo socket.</summary>
public sealed class Socks5UdpRelay : IAsyncDisposable
{
    private readonly UdpEchoServer _echo;
    private readonly Socks5UdpRelayOptions _options;
    private readonly IPAddress _address;
    private readonly ProxyProfile _profile;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentBag<Task> _sessions = [];
    private readonly Task _accept;
    private int _datagrams, _forwarded, _associations;
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public int DatagramCount => Volatile.Read(ref _datagrams);
    public int ForwardedPackets => Volatile.Read(ref _forwarded);
    public int AssociateRequests => Volatile.Read(ref _associations);
    public ConcurrentQueue<IPEndPoint> ClientEndpoints { get; } = new();
    public ConcurrentQueue<Exception> UnexpectedErrors { get; } = new();
    public ProxyProfile Profile => _profile;

    public Socks5UdpRelay(UdpEchoServer echo, Socks5UdpRelayOptions? options = null, AddressFamily? relayFamily = null)
    {
        _echo = echo;
        _options = options ?? new();
        _address = (relayFamily ?? echo.EndPoint.AddressFamily) == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback;
        _listener = new TcpListener(_address, 0);
        _listener.Start();
        _profile = new()
        {
            Name = "Loopback SOCKS5 UDP lab", Host = _address.ToString(), Port = Port,
            CredentialsRef = _options.Credentials is null ? null : "lab-secret-reference"
        };
        _accept = Task.Run(async () =>
        {
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                    _sessions.Add(ServeAsync(client, _stop.Token));
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException) { }
        });
    }

    private async Task ServeAsync(TcpClient client, CancellationToken stop)
    {
        using (client)
        using (var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop))
        {
            lifetime.CancelAfter(_options.SessionLifetime);
            var ct = lifetime.Token;
            try
            {
                var stream = client.GetStream();
                var greeting = await ReadAsync(stream, 2, ct);
                if (greeting[0] != 5 || greeting[1] == 0) return;
                var methods = await ReadAsync(stream, greeting[1], ct);
                var method = _options.Credentials is null ? (byte)0 : (byte)2;
                if (!methods.Contains(method)) { await ReplyAsync(stream, [5, 255], ct); return; }
                await ReplyAsync(stream, [5, method], ct);
                if (_options.Credentials is { } credentials)
                {
                    var auth = await ReadAsync(stream, 2, ct);
                    var username = Encoding.UTF8.GetString(await ReadAsync(stream, auth[1], ct));
                    var passwordLength = (await ReadAsync(stream, 1, ct))[0];
                    var password = Encoding.UTF8.GetString(await ReadAsync(stream, passwordLength, ct));
                    var valid = auth[0] == 1 && username == credentials.Username && password == credentials.Password;
                    await ReplyAsync(stream, new byte[] { 1, valid ? (byte)0 : (byte)1 }, ct);
                    if (!valid) return;
                }
                var header = await ReadAsync(stream, 4, ct);
                if (header[0] != 5 || header[1] != 3 || header[2] != 0) return;
                var associatedClient = await ReadAddressAsync(stream, header[3], ct);
                ClientEndpoints.Enqueue(associatedClient);
                int associationNumber = Interlocked.Increment(ref _associations);
                var fault = associationNumber <= _options.FaultAssociations ? _options.Fault : UdpRelayFault.None;
                using var relay = new UdpClient(new IPEndPoint(_address, 0));
                var relayEndpoint = (IPEndPoint)relay.Client.LocalEndPoint!;
                byte[] reply;
                if (_options.AddressMode == UdpRelayAddressMode.Domain)
                {
                    var domain = Encoding.ASCII.GetBytes("localhost");
                    reply = new byte[domain.Length + 7];
                    reply[3] = 3; reply[4] = (byte)domain.Length; domain.CopyTo(reply, 5);
                }
                else
                {
                    var address = _options.AddressMode == UdpRelayAddressMode.Wildcard
                        ? (_address.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any)
                        : _options.AdvertisedAddress ?? relayEndpoint.Address;
                    reply = EncodeEndpoint(address, _options.ZeroRelayPort ? 0 : relayEndpoint.Port, []);
                }
                reply[0] = 5; reply[1] = _options.ReplyCode;
                var relayPort = _options.ZeroRelayPort ? 0 : relayEndpoint.Port;
                reply[^2] = (byte)(relayPort >> 8); reply[^1] = (byte)relayPort;
                await ReplyAsync(stream, reply, ct);
                if (_options.ReplyCode != 0 || _options.ZeroRelayPort) return;
                var control = stream.ReadAsync(new byte[1], ct).AsTask();
                using var upstream = new UdpClient(_echo.EndPoint.AddressFamily);
                upstream.Connect(_echo.EndPoint);
                byte[]? previousPayload = null;
                var relayed = 0;
                if (fault == UdpRelayFault.CloseControlBeforeRelay) { client.Close(); return; }
                while (!ct.IsCancellationRequested)
                {
                    var pending = relay.ReceiveAsync(ct).AsTask();
                    if (await Task.WhenAny(pending, control) == control) { lifetime.Cancel(); break; }
                    var packet = await pending;
                    Interlocked.Increment(ref _datagrams);
                    var tcpRemote = (IPEndPoint)client.Client.RemoteEndPoint!;
                    if (!packet.RemoteEndPoint.Address.Equals(tcpRemote.Address) ||
                        (associatedClient.Port != 0 && associatedClient.Port != packet.RemoteEndPoint.Port)) continue;
                    var expectedTarget = _options.TargetOverride ?? _echo.EndPoint;
                    if (!TryDecode(packet.Buffer, out var target, out var payload) || !target.Equals(expectedTarget)) continue;
                    await upstream.SendAsync(payload, ct);
                    var echoed = await upstream.ReceiveAsync(ct);
                    Interlocked.Increment(ref _forwarded);
                    relayed++;
                    if (!echoed.RemoteEndPoint.Equals(_echo.EndPoint)) continue;
                    // Construct from the independently received echo address/payload; never replay request headers.
                    var response = EncodeEndpoint(expectedTarget.Address, expectedTarget.Port, echoed.Buffer);
                    if (_options.DropEveryNthReply > 0 && relayed % _options.DropEveryNthReply == 0) continue;
                    if (fault == UdpRelayFault.CloseControlBeforeLastReply && relayed >= _options.CloseAfterPackets)
                    { client.Close(); await Task.Delay(30, ct); }
                    switch (fault)
                    {
                        case UdpRelayFault.DropResponses: continue;
                        case UdpRelayFault.WrongPayload: response[^1] ^= 1; break;
                        case UdpRelayFault.WrongTargetAddress: response[4] ^= 1; break;
                        case UdpRelayFault.WrongTargetPort: response[response.Length - echoed.Buffer.Length - 1] ^= 1; break;
                        case UdpRelayFault.NonzeroReserved: response[1] = 1; break;
                        case UdpRelayFault.Fragmented: response[2] = _options.FragmentValue; break;
                        case UdpRelayFault.Truncated: response = response[..5]; break;
                        case UdpRelayFault.DomainTarget: response[3] = 3; break;
                        case UdpRelayFault.WrongAddressType: response[3] = 9; break;
                        case UdpRelayFault.WrongPayloadLength: response = [.. response, 0]; break;
                        case UdpRelayFault.StaleThenValid:
                            var stale = EncodeEndpoint(expectedTarget.Address, expectedTarget.Port, previousPayload ?? new byte[64]);
                            await relay.SendAsync(stale, packet.RemoteEndPoint, ct);
                            await relay.SendAsync(new byte[] { 0, 0, 1, 1 }, packet.RemoteEndPoint, ct);
                            break;
                        case UdpRelayFault.WrongOuterSource:
                            using (var unrelated = new UdpClient(_address.AddressFamily))
                                await unrelated.SendAsync(response, packet.RemoteEndPoint, ct);
                            continue;
                    }
                    previousPayload = echoed.Buffer;
                    await relay.SendAsync(response, packet.RemoteEndPoint, ct);
                    if (fault == UdpRelayFault.CloseControlBeforeLastReply && relayed >= _options.CloseAfterPackets) return;
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or EndOfStreamException or IOException or SocketException or ObjectDisposedException) { }
            catch (Exception ex) { UnexpectedErrors.Enqueue(ex); }
        }
    }

    private async Task ReplyAsync(Stream stream, byte[] bytes, CancellationToken ct)
    {
        if (_options.FragmentTcpReplies)
        { foreach (var value in bytes) { await stream.WriteAsync(new[] { value }, ct); await Task.Yield(); } }
        else await stream.WriteAsync(bytes, ct);
    }
    private static async Task<byte[]> ReadAsync(Stream stream, int count, CancellationToken ct)
    { var bytes = new byte[count]; await stream.ReadExactlyAsync(bytes, ct); return bytes; }
    private static async Task<IPEndPoint> ReadAddressAsync(Stream stream, byte type, CancellationToken ct)
    {
        if (type is not (1 or 4)) throw new IOException("Lab expects a literal client endpoint.");
        var address = new IPAddress(await ReadAsync(stream, type == 1 ? 4 : 16, ct));
        var port = await ReadAsync(stream, 2, ct);
        return new(address, (port[0] << 8) | port[1]);
    }
    private static byte[] EncodeEndpoint(IPAddress address, int port, byte[] payload)
    {
        var bytes = address.GetAddressBytes();
        var packet = new byte[bytes.Length + 6 + payload.Length];
        packet[3] = address.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
        bytes.CopyTo(packet, 4); packet[bytes.Length + 4] = (byte)(port >> 8); packet[bytes.Length + 5] = (byte)port;
        payload.CopyTo(packet, bytes.Length + 6);
        return packet;
    }
    private static bool TryDecode(byte[] bytes, out IPEndPoint endpoint, out byte[] payload)
    {
        endpoint = new(IPAddress.Any, 0); payload = [];
        if (bytes.Length < 4 || bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 0) return false;
        var length = bytes[3] switch { 1 => 4, 4 => 16, _ => 0 };
        if (length == 0 || bytes.Length < length + 6) return false;
        endpoint = new(new IPAddress(bytes.AsSpan(4, length)), (bytes[length + 4] << 8) | bytes[length + 5]);
        payload = bytes[(length + 6)..]; return true;
    }
    public async ValueTask DisposeAsync()
    {
        _stop.Cancel(); _listener.Stop();
        try { await _accept; await Task.WhenAll(_sessions.ToArray()); }
        finally { _stop.Dispose(); }
    }
}
