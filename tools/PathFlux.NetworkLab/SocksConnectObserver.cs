using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using PathFlux.Domain;
namespace PathFlux.NetworkLab;

/// <summary>Loopback-only observer forwarding a single IPv4 destination through a local SOCKS5 Docker endpoint.</summary>
public sealed class SocksConnectObserver : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> clients = [];
    private readonly Task loop;
    private readonly IPAddress target;
    private readonly int targetPort;
    private readonly bool refuse;
    private int requests, forwards;
    public int Requests => Volatile.Read(ref requests);
    public int Forwards => Volatile.Read(ref forwards);
    public ProxyProfile Profile { get; }
    public SocksConnectObserver(IPAddress target, int targetPort, bool refuse = false)
    {
        this.target = target; this.targetPort = targetPort; this.refuse = refuse;
        listener.Start(); Profile = new() { Host = "127.0.0.1", Port = ((IPEndPoint)listener.LocalEndpoint).Port };
        loop = AcceptAsync();
    }
    private async Task AcceptAsync()
    {
        try { while (!stop.IsCancellationRequested) clients.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token))); }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException) { }
    }
    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
        {
            deadline.CancelAfter(TimeSpan.FromSeconds(15)); var ct = deadline.Token;
            try
            {
                var stream = client.GetStream(); var hello = new byte[2]; await stream.ReadExactlyAsync(hello, ct);
                if (hello[0] != 5 || hello[1] is < 1 or > 8) return;
                var methods = new byte[hello[1]]; await stream.ReadExactlyAsync(methods, ct);
                if (!methods.Contains((byte)0)) return;
                await stream.WriteAsync(new byte[] { 5, 0 }, ct);
                var request = new byte[10]; await stream.ReadExactlyAsync(request.AsMemory(0, 4), ct);
                if (request[0] != 5 || request[1] != 1 || request[2] != 0 || request[3] != 1) return;
                await stream.ReadExactlyAsync(request.AsMemory(4), ct);
                if (!new IPAddress(request.AsSpan(4, 4)).Equals(target) || ((request[8] << 8) | request[9]) != targetPort) return;
                Interlocked.Increment(ref requests);
                if (refuse) { await stream.WriteAsync(new byte[] { 5, 5, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
                using var upstream = new TcpClient(); await upstream.ConnectAsync(IPAddress.Loopback, 1080, ct);
                var other = upstream.GetStream(); await other.WriteAsync(new byte[] { 5, 1, 0 }, ct);
                var selection = new byte[2]; await other.ReadExactlyAsync(selection, ct);
                if (!selection.AsSpan().SequenceEqual(new byte[] { 5, 0 })) return;
                await other.WriteAsync(request, ct);
                var header = new byte[4]; await other.ReadExactlyAsync(header, ct);
                if (header[0] != 5 || header[1] != 0 || header[2] != 0) return;
                int length = header[3] switch { 1 => 4, 4 => 16, 3 => await ReadLengthAsync(other, ct), _ => throw new IOException() };
                await other.ReadExactlyAsync(new byte[length + 2], ct);
                Interlocked.Increment(ref forwards);
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, ct);
                var outbound = stream.CopyToAsync(other, ct); var inbound = other.CopyToAsync(stream, ct);
                await Task.WhenAny(outbound, inbound); deadline.Cancel();
                try { await Task.WhenAll(outbound, inbound); } catch (OperationCanceledException) { }
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        }
    }
    private static async Task<int> ReadLengthAsync(Stream stream, CancellationToken ct)
    { var b = new byte[1]; await stream.ReadExactlyAsync(b, ct); if (b[0] == 0) throw new IOException(); return b[0]; }
    public async ValueTask DisposeAsync()
    { stop.Cancel(); listener.Stop(); await loop; await Task.WhenAll(clients.ToArray()); stop.Dispose(); }
}
