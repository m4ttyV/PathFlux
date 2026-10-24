using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
namespace PathFlux.NetworkLab;

public static class TlsProbe
{
    public static async Task<ProbeResult> RunAsync(string ip, int port, string serverName, CancellationToken ct)
    {
        if (!IPAddress.TryParse(ip, out var address) || port is < 1 or > 65535 || Uri.CheckHostName(serverName) != UriHostNameType.Dns)
            return new(false, "InvalidTlsTarget");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(8));
        using var tcp = new TcpClient(address.AddressFamily);
        string stage = "Connect";
        try
        {
            await tcp.ConnectAsync(address, port, deadline.Token);
            await using var tls = new SslStream(tcp.GetStream(), false);
            stage = "Handshake";
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = serverName }, deadline.Token);
            stage = "HttpWrite";
            await tls.WriteAsync(Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {serverName}\r\nConnection: close\r\n\r\n"), deadline.Token);
            stage = "HttpRead";
            var response = new byte[1024]; int size = await tls.ReadAsync(response, deadline.Token);
            var text = Encoding.ASCII.GetString(response, 0, size);
            return new(text.StartsWith("HTTP/1.1 2", StringComparison.Ordinal) || text.StartsWith("HTTP/1.1 3", StringComparison.Ordinal), "TlsHttpChecked");
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
        { return new(false, "Tls" + stage + "_" + ex.GetType().Name); }
    }
}
