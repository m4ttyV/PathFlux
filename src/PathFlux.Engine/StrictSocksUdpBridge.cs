using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Domain;

namespace PathFlux.Engine;

// Experimental transport; only the agent owns production instances.
internal sealed record UdpRelayBinding(int? DockerPortFirst = null, int? DockerPortLast = null)
{
    public IPEndPoint Resolve(IPEndPoint tcpPeer, IPEndPoint advertised)
    {
        if (advertised.Port == 0) throw new IOException("ZeroUdpRelayPort");
        if (DockerPortFirst is { } first && DockerPortLast is { } last)
        {
            if (!tcpPeer.Address.Equals(IPAddress.Loopback) || first < 1 || last > 65535 || last < first ||
                advertised.Port < first || advertised.Port > last) throw new IOException("UnpublishedDockerUdpPort");
            // Explicit host-published mode: never route to or remember the container address.
            return new(tcpPeer.Address, advertised.Port);
        }
        if (DockerPortFirst is not null || DockerPortLast is not null) throw new IOException("IncompleteDockerPortRange");
        var address = advertised.Address.Equals(IPAddress.Any) || advertised.Address.Equals(IPAddress.IPv6Any)
            ? tcpPeer.Address : advertised.Address;
        if (address.IsIPv6Multicast || address.Equals(IPAddress.Broadcast) ||
            (address.AddressFamily == AddressFamily.InterNetwork && address.GetAddressBytes()[0] >= 224))
            throw new IOException("InvalidUdpRelayAddress");
        return new(address, advertised.Port);
    }
}

/// <summary>Authenticated loopback UDP-only SOCKS inlet. Only the upstream relay receives payloads.
/// Fragments are deliberately unsupported and dropped in both directions (RFC 1928 section 7).
/// Upstream reconnect never replays queued packets; downstream socket survives association loss.</summary>
internal sealed class StrictSocksUdpBridge : IAsyncDisposable
{
    private readonly IPEndPoint _upstream;
    private readonly ProxyCredentials? _credentials;
    private readonly UdpRelayBinding _binding;
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<long, Task> _sessions = new();
    private readonly SemaphoreSlim _slots = new(128);
    private readonly Task _accept;
    private long _nextSession;
    private int _disposed, _attempts, _active, _failed;
    private long _associations, _reconnects, _fragments, _invalid, _sent, _received;
    private string? _lastError;
    public ProxyCredentials LocalCredentials { get; } = new(Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
    public IPEndPoint EndPoint => (IPEndPoint)_listener.LocalEndpoint;
    public long Associations => Volatile.Read(ref _associations);
    public bool HasFailed => Volatile.Read(ref _failed) != 0;
    public UdpBridgeStatistics Snapshot(Guid profileId) => new(profileId, HasFailed ? "Failed" : Volatile.Read(ref _disposed) != 0 ? "Stopped" :
        Volatile.Read(ref _active) > 0 ? "Active" : Volatile.Read(ref _attempts) > 0 ? "Waiting / Reconnecting" : "Listening",
        Volatile.Read(ref _active), SentPackets, ReceivedPackets, Reconnects, DroppedFragments, DroppedInvalid, Volatile.Read(ref _lastError));
    public int AssociateAttempts => Volatile.Read(ref _attempts);
    public IPEndPoint? LastAdvertisedRelay { get; private set; }
    public IPEndPoint? LastEffectiveRelay { get; private set; }
    public long Reconnects => Volatile.Read(ref _reconnects);
    public long DroppedFragments => Volatile.Read(ref _fragments);
    public long DroppedInvalid => Volatile.Read(ref _invalid);
    public long SentPackets => Volatile.Read(ref _sent);
    public long ReceivedPackets => Volatile.Read(ref _received);

    public StrictSocksUdpBridge(IPEndPoint upstream, UdpRelayBinding? binding = null, ProxyCredentials? credentials = null)
    {
        if (!PathFlux.Application.ExperimentalUdpPolicy.IsUnicast(upstream.Address) || upstream.Port == 0) throw new ArgumentException("UnicastProxyRequired", nameof(upstream));
        _upstream = upstream; _binding = binding ?? new(); _credentials = credentials;
        _listener.Start(128); _accept = AcceptAsync();
    }

    private async Task AcceptAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                if (!_slots.Wait(0)) { client.Dispose(); continue; }
                long id = Interlocked.Increment(ref _nextSession);
                var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _sessions[id] = RunSessionAsync(id, client, registered.Task);
                registered.SetResult();
            }
        }
        catch (Exception ex) when (Expected(ex)) { if (!_stop.IsCancellationRequested) FailClosed(); }
        catch { FailClosed(); }
    }
    private async Task RunSessionAsync(long id, TcpClient client, Task registered)
    {
        await registered;
        try { await ServeAsync(client, _stop.Token); }
        catch { FailClosed(); }
        finally { _slots.Release(); _sessions.TryRemove(id, out _); }
    }

    internal void FailClosed()
    {
        Interlocked.Exchange(ref _failed, 1);
        Volatile.Write(ref _lastError, "UDP-посредник аварийно остановлен. UDP заблокирован без Direct fallback; остановите движок перед повторным запуском.");
        _stop.Cancel(); _listener.Stop();
    }
    private void RecordError(Exception ex)
    {
        string message = ex switch
        {
            OperationCanceledException => "Истекло время ожидания UDP-ассоциации.",
            SocketException => "SOCKS5 или UDP-релей недоступен; пакеты не отправляются напрямую.",
            IOException when ex.Message == "UnpublishedDockerUdpPort" => "Dante вернул порт вне разрешённого диапазона Docker NAT.",
            IOException when ex.Message == "ZeroUdpRelayPort" => "SOCKS5 вернул нулевой UDP-порт.",
            IOException when ex.Message == "LiteralUdpEndpointRequired" => "SOCKS5 вернул доменное имя релея; поддерживается только буквальный IP.",
            IOException when ex.Message == "SocksAuthenticationRejected" => "SOCKS5 отклонил авторизацию UDP-ассоциации.",
            IOException when ex.Message == "UdpAssociateRejected" => "SOCKS5 отклонил UDP ASSOCIATE.",
            _ => "Управляющее соединение UDP-ассоциации разорвано; выполняется переподключение."
        };
        Volatile.Write(ref _lastError, message);
    }

    private async Task ServeAsync(TcpClient client, CancellationToken stop)
    {
        using (client)
        using (var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop))
        {
            Task[] tasks = [];
            try
            {
                var stream = client.GetStream();
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                handshake.CancelAfter(TimeSpan.FromSeconds(10));
                var ct = handshake.Token;
                var greeting = await ReadAsync(stream, 2, ct);
                if (greeting[0] != 5 || greeting[1] == 0) return;
                var methods = await ReadAsync(stream, greeting[1], ct);
                if (!methods.Contains((byte)2)) { await stream.WriteAsync(new byte[] { 5, 255 }, ct); return; }
                await stream.WriteAsync(new byte[] { 5, 2 }, ct);
                var auth = await ReadAsync(stream, 2, ct);
                var user = await ReadAsync(stream, auth[1], ct);
                int length = (await ReadAsync(stream, 1, ct))[0];
                var password = await ReadAsync(stream, length, ct);
                bool valid = auth[0] == 1 && CryptographicOperations.FixedTimeEquals(user, Encoding.UTF8.GetBytes(LocalCredentials.Username)) &&
                    CryptographicOperations.FixedTimeEquals(password, Encoding.UTF8.GetBytes(LocalCredentials.Password));
                await stream.WriteAsync(new byte[] { 1, valid ? (byte)0 : (byte)1 }, ct);
                if (!valid) return;
                var request = await ReadAsync(stream, 4, ct);
                if (request[0] != 5 || request[1] != 3 || request[2] != 0)
                { await stream.WriteAsync(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
                // sing sends the destination here. It is not a trustworthy client UDP source port.
                await ReadEndpointAsync(stream, request[3], ct);
                using var local = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                local.Client.ReceiveBufferSize = 256 * 1024;
                using var state = new SessionState();
                // Do not announce success until the first upstream association is established.
                var first = await ConnectAsync(ct);
                state.Current = first;
                await stream.WriteAsync(Encode((IPEndPoint)local.Client.LocalEndPoint!, [], socksReply: true), ct);
                tasks = [ReceiveLocalAsync(local, state, lifetime.Token), MaintainUpstreamAsync(local, state, first, lifetime.Token),
                    stream.ReadAsync(new byte[1], lifetime.Token).AsTask()];
                try { await Task.WhenAny(tasks); }
                finally
                {
                    lifetime.Cancel();
                    try { await Task.WhenAll(tasks); } catch (Exception ex) when (Expected(ex)) { }
                }
            }
            catch (Exception ex) when (Expected(ex)) { if (!lifetime.IsCancellationRequested) RecordError(ex); }
            finally
            {
                lifetime.Cancel();
                try { await Task.WhenAll(tasks); } catch (Exception ex) when (Expected(ex)) { if (!stop.IsCancellationRequested) RecordError(ex); }
            }
        }
    }

    private async Task<Association> ConnectAsync(CancellationToken ct)
    {
        var tcp = new TcpClient(_upstream.AddressFamily);
        try
        {
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 10);
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 3);
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
            await tcp.ConnectAsync(_upstream, ct);
            var stream = tcp.GetStream();
            byte method = _credentials is null ? (byte)0 : (byte)2;
            await stream.WriteAsync(new byte[] { 5, 1, method }, ct);
            var choice = await ReadAsync(stream, 2, ct);
            if (choice[0] != 5 || choice[1] != method) throw new IOException("SocksAuthenticationRejected");
            if (_credentials is { } credentials)
            {
                var user = Encoding.UTF8.GetBytes(credentials.Username); var pass = Encoding.UTF8.GetBytes(credentials.Password);
                if (user.Length is < 1 or > 255 || pass.Length is < 1 or > 255) throw new IOException("InvalidCredentialLength");
                await stream.WriteAsync(new byte[] { 1, (byte)user.Length }.Concat(user).Concat(new byte[] { (byte)pass.Length }).Concat(pass).ToArray(), ct);
                var auth = await ReadAsync(stream, 2, ct);
                if (auth[0] != 1 || auth[1] != 0) throw new IOException("SocksAuthenticationRejected");
            }
            // NAT-safe unknown source endpoint, as required by RFC 1928 and Dante Docker deployment.
            await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, ct);
            Interlocked.Increment(ref _attempts);
            var header = await ReadAsync(stream, 4, ct);
            if (header[0] != 5 || header[1] != 0 || header[2] != 0) throw new IOException("UdpAssociateRejected");
            var advertised = await ReadEndpointAsync(stream, header[3], ct);
            LastAdvertisedRelay = advertised;
            var endpoint = _binding.Resolve((IPEndPoint)tcp.Client.RemoteEndPoint!, advertised);
            LastEffectiveRelay = endpoint;
            var udp = new UdpClient(endpoint.AddressFamily);
            udp.Client.ReceiveBufferSize = 256 * 1024;
            try { udp.Connect(endpoint); return new(tcp, udp); }
            catch { udp.Dispose(); throw; }
        }
        catch { tcp.Dispose(); throw; }
    }

    private async Task MaintainUpstreamAsync(UdpClient local, SessionState state, Association first, CancellationToken ct)
    {
        Association? association = first; int backoff = 250;
        while (!ct.IsCancellationRequested)
        {
            if (association is null)
            {
                try
                {
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(10));
                    association = await ConnectAsync(deadline.Token);
                    lock (state.Gate)
                    {
                        if (state.Closed) { association.Dispose(); throw new OperationCanceledException(ct); }
                        state.Current = association;
                    }
                    Interlocked.Increment(ref _reconnects);
                }
                catch (Exception ex) when (Expected(ex))
                { if (!ct.IsCancellationRequested) RecordError(ex); await Task.Delay(backoff, ct); backoff = Math.Min(2000, backoff * 2); continue; }
            }
            Interlocked.Increment(ref _associations);
            Interlocked.Increment(ref _active);
            using var epoch = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var control = association.Tcp.GetStream().ReadAsync(new byte[1], epoch.Token).AsTask();
            var receive = ReceiveUpstreamAsync(local, state, association, control, epoch.Token);
            try { await Task.WhenAny(control, receive); }
            finally
            {
                Interlocked.Decrement(ref _active);
                lock (state.Gate) { if (state.Current == association) state.Current = null; }
                epoch.Cancel(); association.Dispose(); association = null;
            }
            if (!ct.IsCancellationRequested) RecordError(new IOException());
            try { await Task.WhenAll(control, receive); } catch (Exception ex) when (Expected(ex)) { if (!ct.IsCancellationRequested) RecordError(ex); }
            await Task.Delay(backoff, ct); backoff = Math.Min(2000, backoff * 2);
        }
    }

    private async Task ReceiveLocalAsync(UdpClient local, SessionState state, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await local.ReceiveAsync(ct);
            if (!packet.RemoteEndPoint.Address.Equals(IPAddress.Loopback) || !Validate(packet.Buffer, out var target)) continue;
            Association? current;
            lock (state.Gate)
            {
                state.Client ??= packet.RemoteEndPoint;
                if (!state.Client.Equals(packet.RemoteEndPoint)) continue;
                if (state.Targets.Count >= 256 && !state.Targets.Contains(target!)) continue;
                state.Targets.Add(target!); current = state.Current;
            }
            if (current is null || !current.IsOpen) continue; // Drop while reconnecting. Never send to destination directly.
            try { await current.Udp.SendAsync(packet.Buffer, ct); Interlocked.Increment(ref _sent); }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
        }
    }

    private async Task ReceiveUpstreamAsync(UdpClient local, SessionState state, Association association, Task control, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await association.Udp.ReceiveAsync(ct); // Connected socket filters the relay's IP AND port.
            if (!Validate(packet.Buffer, out var target)) continue;
            IPEndPoint? client;
            lock (state.Gate)
            {
                if (state.Current != association || control.IsCompleted || !association.IsOpen || !state.Targets.Contains(target!)) continue;
                client = state.Client;
            }
            if (client is null) continue;
            await local.SendAsync(packet.Buffer, client, ct); Interlocked.Increment(ref _received);
        }
    }

    private bool Validate(byte[] packet, out string? target)
    {
        target = null;
        if (packet.Length >= 3 && packet[2] != 0) { Interlocked.Increment(ref _fragments); return false; }
        if (!TryDecode(packet, out var endpoint, out _)) { Interlocked.Increment(ref _invalid); return false; }
        target = endpoint!.ToString(); return true;
    }
    internal static bool TryDecode(byte[] packet, out IPEndPoint? endpoint, out int payloadOffset)
    {
        endpoint = null; payloadOffset = 0;
        if (packet.Length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0) return false;
        int length = packet[3] switch { 1 => 4, 4 => 16, _ => 0 };
        if (length == 0 || packet.Length < length + 6) return false;
        int port = (packet[length + 4] << 8) | packet[length + 5];
        if (port == 0) return false;
        var address = new IPAddress(packet.AsSpan(4, length));
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast) || address.IsIPv6Multicast ||
            (length == 4 && address.GetAddressBytes()[0] >= 224)) return false;
        endpoint = new(address, port); payloadOffset = length + 6; return true;
    }
    internal static byte[] Encode(IPEndPoint endpoint, byte[] payload, bool socksReply = false)
    {
        var address = endpoint.Address.GetAddressBytes(); var bytes = new byte[address.Length + 6 + payload.Length];
        bytes[0] = socksReply ? (byte)5 : (byte)0; bytes[3] = address.Length == 4 ? (byte)1 : (byte)4;
        address.CopyTo(bytes, 4); bytes[address.Length + 4] = (byte)(endpoint.Port >> 8); bytes[address.Length + 5] = (byte)endpoint.Port;
        payload.CopyTo(bytes, address.Length + 6); return bytes;
    }
    private static async Task<byte[]> ReadAsync(Stream stream, int count, CancellationToken ct)
    { var bytes = new byte[count]; await stream.ReadExactlyAsync(bytes, ct); return bytes; }
    private static async Task<IPEndPoint> ReadEndpointAsync(Stream stream, byte type, CancellationToken ct)
    {
        // Literal endpoints only: never resolve a relay domain using system DNS under TUN.
        if (type is not (1 or 4)) throw new IOException("LiteralUdpEndpointRequired");
        var address = new IPAddress(await ReadAsync(stream, type == 1 ? 4 : 16, ct));
        var port = await ReadAsync(stream, 2, ct); return new(address, (port[0] << 8) | port[1]);
    }
    private static bool Expected(Exception ex) => ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException;
    private sealed class Association(TcpClient tcp, UdpClient udp) : IDisposable
    {
        private int _disposed;
        public TcpClient Tcp => tcp;
        public UdpClient Udp => udp;
        public bool IsOpen
        {
            get
            {
                if (Volatile.Read(ref _disposed) != 0) return false;
                try { return tcp.Client is { } socket && !socket.Poll(0, SelectMode.SelectRead); }
                catch (Exception ex) when (Expected(ex)) { return false; }
            }
        }
        public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) { udp.Dispose(); tcp.Dispose(); } }
    }
    private sealed class SessionState : IDisposable
    {
        public object Gate { get; } = new();
        public Association? Current;
        public IPEndPoint? Client;
        public HashSet<string> Targets { get; } = [];
        public bool Closed;
        public void Dispose() { lock (Gate) { Closed = true; Current?.Dispose(); Current = null; } }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel(); _listener.Stop(); await _accept;
        try { await Task.WhenAll(_sessions.Values); } catch { /* Fatal faults were observed and the transport was closed. */ }
        _slots.Dispose(); _stop.Dispose();
    }
}
