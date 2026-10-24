using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace PathFlux.NetworkLab;

// No Discord authentication or channel join: validates only TLS and RFC 6455 upgrade.
public static class VoiceWebSocketProbe
{
    public static async Task<ProbeResult> RunAsync(string ip, int port, string host, CancellationToken ct)
    {
        if (!IPAddress.TryParse(ip, out var address) || port is < 1 or > 65535 || Uri.CheckHostName(host) != UriHostNameType.Dns)
            return new(false, "InvalidWebSocketTarget");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(8));
        string stage = "Connect";
        try
        {
            using var tcp = new TcpClient(address.AddressFamily);
            await tcp.ConnectAsync(address, port, deadline.Token);
            stage = "TLS";
            await using var tls = new SslStream(tcp.GetStream(), false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, deadline.Token);
            stage = "Upgrade";
            string key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            await tls.WriteAsync(Encoding.ASCII.GetBytes($"GET /?v=8 HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"), deadline.Token);
            using var response = new MemoryStream(); var buffer = new byte[2048];
            while (response.Length < 16384)
            {
                int count = await tls.ReadAsync(buffer, deadline.Token);
                if (count == 0) break;
                response.Write(buffer, 0, count);
                string text = Encoding.ASCII.GetString(response.GetBuffer(), 0, (int)response.Length);
                int end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                if (end < 0) continue;
                var headers = text[..end].Split("\r\n");
                string expected = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
                bool accepted = headers[0].StartsWith("HTTP/1.1 101 ", StringComparison.Ordinal) &&
                    headers.Any(h => h.StartsWith("Sec-WebSocket-Accept:", StringComparison.OrdinalIgnoreCase) && h[(h.IndexOf(':') + 1)..].Trim() == expected);
                return new(accepted, accepted ? "VoiceWebSocketUpgradeChecked_NoAuthentication" : "WebSocketUpgradeRejected");
            }
            return new(false, "WebSocketHeadersIncomplete");
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
        { return new(false, "WebSocket" + stage + "_" + ex.GetType().Name); }
    }
}
