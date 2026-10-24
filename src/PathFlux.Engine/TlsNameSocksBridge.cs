using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Domain;

namespace PathFlux.Engine;

// Agent-owned, authenticated loopback TCP only. TLS bytes are passed through unchanged.
internal sealed class TlsNameSocksBridge : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly SemaphoreSlim slots = new(128);
    private readonly ConcurrentDictionary<long, Task> clients = new();
    private readonly IPEndPoint upstream;
    private readonly ProxyCredentials? credentials;
    private readonly ProxyDohIpv4Resolver? resolver;
    private readonly Func<string, CancellationToken, Task<IPAddress>> resolve;
    private readonly Task accept;
    private long sequence;
    private int disposed;
    private long connections, names, forwards;
    private string? lastError;
    internal string Diagnostic => $"TCP/SNI: соединений {Interlocked.Read(ref connections)}, имён {Interlocked.Read(ref names)}, upstream {Interlocked.Read(ref forwards)}, код {Volatile.Read(ref lastError) ?? "нет"}.";
    internal IPEndPoint EndPoint { get; }
    internal ProxyCredentials LocalCredentials { get; } = new(Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
    internal TlsNameSocksBridge(IPEndPoint upstream, ProxyCredentials? credentials, string dohServer = "https://1.1.1.1/dns-query",
        Func<string, CancellationToken, Task<IPAddress>>? resolveForTesting = null)
    {
        this.upstream = upstream; this.credentials = credentials;
        if (resolveForTesting is not null) resolve = resolveForTesting;
        else { resolver = new(upstream, credentials, dohServer); resolve = resolver.ResolveAsync; }
        listener.Start(); EndPoint = (IPEndPoint)listener.LocalEndpoint; accept = AcceptAsync();
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                await slots.WaitAsync(stop.Token);
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stop.Token); }
                catch { slots.Release(); throw; }
                long id = Interlocked.Increment(ref sequence);
                var registered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                clients[id] = ServeAsync(id, client, registered.Task); registered.SetResult();
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
        finally { stop.Cancel(); listener.Stop(); }
    }
    private static async Task<byte[]> ReadAsync(Stream stream, int length, CancellationToken ct)
    { var bytes = new byte[length]; await stream.ReadExactlyAsync(bytes, ct); return bytes; }
    private async Task ServeAsync(long id, TcpClient client, Task registered)
    {
        await registered;
        using (client)
        using (var lifetime = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
        {
            string stage = "LocalHandshake";
            try
            {
                Interlocked.Increment(ref connections);
                var stream = client.GetStream();
                using var handshake = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); handshake.CancelAfter(TimeSpan.FromSeconds(10));
                var ct = handshake.Token;
                var greeting = await ReadAsync(stream, 2, ct);
                if (greeting[0] != 5 || greeting[1] == 0) return;
                if (!(await ReadAsync(stream, greeting[1], ct)).Contains((byte)2)) { await stream.WriteAsync(new byte[] { 5, 255 }, ct); return; }
                await stream.WriteAsync(new byte[] { 5, 2 }, ct);
                var auth = await ReadAsync(stream, 2, ct); var user = await ReadAsync(stream, auth[1], ct);
                var pass = await ReadAsync(stream, (await ReadAsync(stream, 1, ct))[0], ct);
                bool valid = auth[0] == 1 && CryptographicOperations.FixedTimeEquals(user, Encoding.UTF8.GetBytes(LocalCredentials.Username)) &&
                    CryptographicOperations.FixedTimeEquals(pass, Encoding.UTF8.GetBytes(LocalCredentials.Password));
                await stream.WriteAsync(new byte[] { 1, valid ? (byte)0 : (byte)1 }, ct); if (!valid) return;
                var header = await ReadAsync(stream, 4, ct);
                if (header[0] != 5 || header[1] != 1 || header[2] != 0) return;
                int length = header[3] switch { 1 => 4, 4 => 16, 3 => (await ReadAsync(stream, 1, ct))[0], _ => throw new IOException() };
                if (length == 0) return;
                var address = await ReadAsync(stream, length, ct); var port = await ReadAsync(stream, 2, ct);
                // TUN must acknowledge TCP before the application can send ClientHello.
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, ct);
                stage = "ClientHello";
                var hello = await PeekClientHelloAsync(stream, ct);
                if (hello.ServerName is not null) Interlocked.Increment(ref names);
                stage = "UpstreamConnect";
                using var remote = new TcpClient(upstream.AddressFamily);
                await remote.ConnectAsync(upstream, ct); var other = remote.GetStream();
                await other.WriteAsync(credentials is null ? new byte[] { 5, 1, 0 } : new byte[] { 5, 1, 2 }, ct);
                var method = await ReadAsync(other, 2, ct);
                if (method[0] != 5 || method[1] != (credentials is null ? 0 : 2)) { Volatile.Write(ref lastError, "UpstreamMethodRejected"); return; }
                if (credentials is not null)
                {
                    var u = Encoding.UTF8.GetBytes(credentials.Username); var p = Encoding.UTF8.GetBytes(credentials.Password);
                    if (u.Length is < 1 or > 255 || p.Length is < 1 or > 255) return;
                    await other.WriteAsync(new byte[] { 1, (byte)u.Length }.Concat(u).Concat(new byte[] { (byte)p.Length }).Concat(p).ToArray(), ct);
                    if (!(await ReadAsync(other, 2, ct)).AsSpan().SequenceEqual(new byte[] { 1, 0 })) return;
                }
                byte type = header[3];
                if (header[3] == 4 && hello.ServerName is { } name)
                {
                    stage = "ResolveIPv4";
                    var ipv4 = await resolve(name, ct);
                    if (ipv4.AddressFamily != AddressFamily.InterNetwork) throw new IOException("NoIPv4Address");
                    type = 1; address = ipv4.GetAddressBytes();
                }
                byte[] prefix = type == 3 ? [5, 1, 0, type, (byte)address.Length] : [5, 1, 0, type];
                stage = "UpstreamRequest";
                await other.WriteAsync(prefix.Concat(address).Concat(port).ToArray(), ct);
                var reply = await ReadAsync(other, 4, ct);
                if (reply[0] != 5 || reply[1] != 0 || reply[2] != 0) { Volatile.Write(ref lastError, "UpstreamReply_" + reply[1]); return; }
                int replyLength = reply[3] switch { 1 => 4, 4 => 16, 3 => (await ReadAsync(other, 1, ct))[0], _ => throw new IOException() };
                await ReadAsync(other, replyLength + 2, ct);
                Interlocked.Increment(ref forwards); stage = "Relay";
                if (hello.Bytes.Length > 0) await other.WriteAsync(hello.Bytes, ct);
                var outgoing = stream.CopyToAsync(other, lifetime.Token); var incoming = other.CopyToAsync(stream, lifetime.Token);
                try { await Task.WhenAny(outgoing, incoming); }
                finally { lifetime.Cancel(); try { await Task.WhenAll(outgoing, incoming); } catch (Exception ex) when (Expected(ex)) { } }
            }
            catch (Exception ex) when (Expected(ex)) { if (!stop.IsCancellationRequested) Volatile.Write(ref lastError, stage + "_" + ex.GetType().Name); }
            catch { Volatile.Write(ref lastError, stage + "_UnexpectedFailure"); }
            finally { slots.Release(); clients.TryRemove(id, out _); }
        }
    }
    private static bool Expected(Exception ex) => ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException or AuthenticationException or HttpRequestException or System.Text.Json.JsonException;
    internal sealed record ClientHello(string? ServerName, byte[] Bytes);
    internal static async Task<ClientHello> PeekClientHelloAsync(Stream source, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(TimeSpan.FromMilliseconds(300));
        using var capture = new CaptureStream(source);
        string? name = null;
        using var parser = new SslStream(capture, leaveInnerStreamOpen: true);
        try
        {
            await parser.AuthenticateAsServerAsync((_, hello, _, _) =>
            {
                if (Uri.CheckHostName(hello.ServerName) == UriHostNameType.Dns && hello.ServerName.Length <= 253 && hello.ServerName.All(c => c < 128)) name = hello.ServerName;
                // Never supply a certificate or finish TLS. Suppress parser writes; replay original bytes.
                throw new AuthenticationException("ClientHelloCaptured");
            }, null, timeout.Token);
        }
        catch (Exception ex) when (ex is AuthenticationException || ex is OperationCanceledException && !ct.IsCancellationRequested) { }
        catch (IOException) when (!capture.LimitReached) { }
        if (capture.LimitReached) throw new IOException("ClientHelloLimit");
        return new(name, capture.Bytes.ToArray());
    }
    private sealed class CaptureStream(Stream source) : Stream
    {
        internal MemoryStream Bytes { get; } = new();
        internal bool LimitReached { get; private set; }
        public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            int remaining = 65536 - (int)Bytes.Length;
            if (remaining == 0) { LimitReached = true; throw new IOException("ClientHelloLimit"); }
            int n = await source.ReadAsync(buffer[..Math.Min(buffer.Length, remaining)], ct);
            Bytes.Write(buffer.Span[..n]); return n;
        }
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) { }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => ValueTask.CompletedTask;
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(); public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) Bytes.Dispose(); base.Dispose(disposing); }
    }
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stop.Cancel(); listener.Stop(); await accept; await Task.WhenAll(clients.Values); resolver?.Dispose(); slots.Dispose(); stop.Dispose();
    }
}
