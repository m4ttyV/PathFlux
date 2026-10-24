using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Engine;
namespace PathFlux.NetworkLab;

public static class UdpProbe
{
    public static async Task<ProbeResult> StunAsync(string host, int port, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new UdpClient(AddressFamily.InterNetwork); client.Connect(IPAddress.Parse(host), port);
        var request = new byte[20]; request[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), 0x2112a442); RandomNumberGenerator.Fill(request.AsSpan(8));
        try
        {
            await client.SendAsync(request, deadline.Token);
            var packet = (await client.ReceiveAsync(deadline.Token)).Buffer;
            bool valid = packet.Length >= 20 && packet[0] == 1 && packet[1] == 1 &&
                BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(2)) == packet.Length - 20 &&
                packet.AsSpan(4, 16).SequenceEqual(request.AsSpan(4));
            return new(valid, "StunBindingTransactionChecked", 1, valid ? 1 : 0);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException) { return new(false, ex.GetType().Name, 1, 0); }
    }

    internal static async Task<ProbeResult> DnsThroughBridgeAsync(StrictSocksUdpBridge bridge, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(5));
        using var tcp = new TcpClient(); await tcp.ConnectAsync(bridge.EndPoint, deadline.Token); var stream = tcp.GetStream();
        await stream.WriteAsync(new byte[] { 5, 1, 2 }, deadline.Token); var choice = new byte[2]; await stream.ReadExactlyAsync(choice, deadline.Token);
        if (!choice.AsSpan().SequenceEqual(new byte[] { 5, 2 })) return new(false, "LocalAuthRequired");
        var user = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Username); var pass = Encoding.UTF8.GetBytes(bridge.LocalCredentials.Password);
        await stream.WriteAsync(new byte[] { 1, (byte)user.Length }.Concat(user).Concat(new byte[] { (byte)pass.Length }).Concat(pass).ToArray(), deadline.Token);
        await stream.ReadExactlyAsync(choice, deadline.Token);
        if (!choice.AsSpan().SequenceEqual(new byte[] { 1, 0 })) return new(false, "LocalAuthFailed");
        await stream.WriteAsync(new byte[] { 5, 3, 0, 1, 0, 0, 0, 0, 0, 0 }, deadline.Token);
        var response = new byte[10]; await stream.ReadExactlyAsync(response, deadline.Token);
        if (response[0] != 5 || response[1] != 0 || response[2] != 0 || response[3] != 1) return new(false, "LocalAssociateFailed");
        using var udp = new UdpClient(); udp.Connect(new IPAddress(response.AsSpan(4, 4)), BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(8)));
        var request = DnsRequest(); var target = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53);
        await udp.SendAsync(StrictSocksUdpBridge.Encode(target, request), deadline.Token);
        var packet = (await udp.ReceiveAsync(deadline.Token)).Buffer;
        bool valid = StrictSocksUdpBridge.TryDecode(packet, out var source, out int offset) && source!.Equals(target) && ValidDnsReply(packet.AsSpan(offset), request);
        return new(valid, "DnsThroughStrictDockerBridgeChecked", 1, valid ? 1 : 0);
    }

    public static async Task<ProbeResult> StreamAsync(string host, int port, int count, int minimum, CancellationToken ct)
    {
        if (!IPAddress.TryParse(host, out var address) || count is < 1 or > 10000 || minimum < 0 || minimum > count) return new(false, "InvalidStreamProbe");
        using var client = new UdpClient(address.AddressFamily); client.Connect(address, port);
        int received = 0;
        for (int i = 0; i < count; i++)
        {
            var nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(i % 3 == 0 ? 1200 : i % 3 == 1 ? 512 : 64);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromMilliseconds(350));
            try
            {
                await client.SendAsync(nonce, deadline.Token);
                while (!deadline.IsCancellationRequested)
                {
                    var packet = await client.ReceiveAsync(deadline.Token);
                    if (packet.Buffer.AsSpan().SequenceEqual(nonce)) { received++; break; }
                }
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException) { ct.ThrowIfCancellationRequested(); }
            await Task.Delay(20, ct);
        }
        return new(received >= minimum, "UdpSameSocketStream", count, received);
    }

    public static async Task<ProbeResult> DnsAsync(string host, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(3));
        using var client = new UdpClient(AddressFamily.InterNetwork); client.Connect(IPAddress.Parse(host), 53);
        var request = DnsRequest();
        try
        {
            await client.SendAsync(request, deadline.Token);
            var packet = (await client.ReceiveAsync(deadline.Token)).Buffer;
            bool valid = ValidDnsReply(packet, request);
            return new(valid, "DnsTransactionChecked", 1, valid ? 1 : 0);
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException) { return new(false, ex.GetType().Name, 1, 0); }
    }
    private static byte[] DnsRequest()
    {
        byte[] request = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1];
        RandomNumberGenerator.Fill(request.AsSpan(0, 2)); return request;
    }
    private static bool ValidDnsReply(ReadOnlySpan<byte> packet, byte[] request) => packet.Length >= request.Length && packet[0] == request[0] && packet[1] == request[1] &&
        (packet[2] & 0x82) == 0x80 && (packet[3] & 15) == 0 && packet[4] == 0 && packet[5] == 1 && packet.Slice(12, request.Length - 12).SequenceEqual(request.AsSpan(12));
    public static async Task<ProbeResult> RunAsync(string host, int port, byte[] nonce, CancellationToken ct)
    {
        if (nonce.Length != 64 || !IPAddress.TryParse(host, out var address) || port is < 1 or > 65535) return new(false, "InvalidProbe");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(2));
        using var client = new UdpClient(address.AddressFamily);
        client.Connect(address, port);
        try
        {
            await client.SendAsync(nonce, deadline.Token);
            var response = await client.ReceiveAsync(deadline.Token);
            return new(response.RemoteEndPoint.Equals(new IPEndPoint(address, port)) && response.Buffer.AsSpan().SequenceEqual(nonce), "UdpEchoChecked");
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { return new(false, ex.GetType().Name); }
    }
}
