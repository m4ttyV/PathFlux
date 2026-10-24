using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using PathFlux.Domain;
namespace PathFlux.NetworkLab;

public sealed class LabEchoServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> clients = [];
    private readonly Task loop;
    private int echoes;
    public int Echoes => Volatile.Read(ref echoes);
    public IPEndPoint Endpoint => (IPEndPoint)listener.LocalEndpoint;
    public LabEchoServer()
    {
        listener.Start();
        loop = AcceptAsync();
    }
    private async Task AcceptAsync()
    {
        try { while (!stop.IsCancellationRequested) clients.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token))); }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }
    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                var stream = client.GetStream(); var bytes = new byte[64];
                await stream.ReadExactlyAsync(bytes, timeout.Token);
                Interlocked.Increment(ref echoes);
                await stream.WriteAsync(bytes, timeout.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
        }
    }
    public async ValueTask DisposeAsync()
    { stop.Cancel(); listener.Stop(); await loop; await Task.WhenAll(clients.ToArray()); stop.Dispose(); }
}

/// <summary>A loopback-only SOCKS gateway accepting exactly the synthetic lab destination.</summary>
public sealed class LabSocksGateway : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> clients = [];
    private readonly LabEchoServer echo;
    private readonly byte replyCode;
    private int requests;
    public int Requests => Volatile.Read(ref requests);
    private readonly Task loop;
    public ConcurrentQueue<string> ConfirmedPayloadHashes { get; } = new();
    public ProxyProfile Profile { get; }
    public LabSocksGateway(string name, LabEchoServer echo, byte replyCode = 0)
    {
        this.echo = echo; this.replyCode = replyCode; listener.Start();
        Profile = new() { Name = name, Host = "127.0.0.1", Port = ((IPEndPoint)listener.LocalEndpoint).Port };
        loop = AcceptAsync();
    }
    private async Task AcceptAsync()
    {
        try { while (!stop.IsCancellationRequested) clients.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token))); }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException) { }
    }
    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(5)); var ct = timeout.Token;
            try
            {
                var stream = client.GetStream();
                var hello = new byte[2]; await stream.ReadExactlyAsync(hello, ct);
                if (hello[0] != 5 || hello[1] is < 1 or > 8) return;
                var methods = new byte[hello[1]]; await stream.ReadExactlyAsync(methods, ct);
                if (!methods.Contains((byte)0)) { await stream.WriteAsync(new byte[] { 5, 255 }, ct); return; }
                await stream.WriteAsync(new byte[] { 5, 0 }, ct);
                var request = new byte[10]; await stream.ReadExactlyAsync(request.AsMemory(0, 4), ct);
                if (request[0] != 5 || request[1] != 1 || request[2] != 0 || request[3] != 1)
                { await stream.WriteAsync(new byte[] { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
                await stream.ReadExactlyAsync(request.AsMemory(4), ct);
                var target = new IPAddress(request.AsSpan(4, 4)); var port = (request[8] << 8) | request[9];
                if (target.ToString() != LabPolicy.TargetAddress || port != LabPolicy.TargetPort)
                { await stream.WriteAsync(new byte[] { 5, 2, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
                Interlocked.Increment(ref requests);
                if (replyCode != 0) { await stream.WriteAsync(new byte[] { 5, replyCode, 0, 1, 0, 0, 0, 0, 0, 0 }, ct); return; }
                using var upstream = new TcpClient(); await upstream.ConnectAsync(echo.Endpoint, ct);
                await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 }, ct);
                var payload = new byte[64]; await stream.ReadExactlyAsync(payload, ct);
                var other = upstream.GetStream(); await other.WriteAsync(payload, ct);
                var response = new byte[64]; await other.ReadExactlyAsync(response, ct);
                if (!payload.AsSpan().SequenceEqual(response)) return;
                ConfirmedPayloadHashes.Enqueue(Convert.ToHexString(SHA256.HashData(payload)));
                await stream.WriteAsync(response, ct);
            }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException) { }
        }
    }
    public async ValueTask DisposeAsync()
    { stop.Cancel(); listener.Stop(); await loop; await Task.WhenAll(clients.ToArray()); stop.Dispose(); }
}
