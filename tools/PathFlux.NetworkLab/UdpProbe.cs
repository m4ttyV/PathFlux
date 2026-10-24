using System.Net;
using System.Net.Sockets;
namespace PathFlux.NetworkLab;

public static class UdpProbe
{
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
