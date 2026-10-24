using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PathFlux.Domain;

namespace PathFlux.Engine;

// Used only by the explicit IPv6 TLS compatibility mode. Never a system DNS replacement.
internal sealed class ProxyDohIpv4Resolver : IDisposable
{
    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly SemaphoreSlim requests = new(4);
    private readonly ConcurrentDictionary<string, (IPAddress Address, DateTimeOffset Until)> cache = new(StringComparer.OrdinalIgnoreCase);
    internal ProxyDohIpv4Resolver(IPEndPoint upstream, ProxyCredentials? credentials, string endpoint)
    {
        this.endpoint = new(endpoint);
        var proxy = new WebProxy(new UriBuilder("socks5", upstream.Address.ToString(), upstream.Port).Uri);
        if (credentials is not null) proxy.Credentials = new NetworkCredential(credentials.Username, credentials.Password);
        client = new(new SocketsHttpHandler { Proxy = proxy, UseProxy = true, AllowAutoRedirect = false,
            UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(5), MaxConnectionsPerServer = 4 }) { Timeout = TimeSpan.FromSeconds(7) };
    }
    internal async Task<IPAddress> ResolveAsync(string host, CancellationToken ct)
    {
        if (cache.TryGetValue(host, out var cached) && cached.Until > DateTimeOffset.UtcNow) return cached.Address;
        await requests.WaitAsync(ct);
        try
        {
            if (cache.TryGetValue(host, out cached) && cached.Until > DateTimeOffset.UtcNow) return cached.Address;
            using var request = new HttpRequestMessage(HttpMethod.Get, endpoint.AbsoluteUri + "?name=" + Uri.EscapeDataString(host) + "&type=A");
            request.Headers.Accept.ParseAdd("application/dns-json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > 65536) throw new IOException("DohResponseLimit");
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            using var body = new MemoryStream(); var buffer = new byte[4096];
            while (true)
            {
                int n = await stream.ReadAsync(buffer, ct); if (n == 0) break;
                if (body.Length + n > 65536) throw new IOException("DohResponseLimit"); body.Write(buffer, 0, n);
            }
            var result = Parse(host, body.ToArray());
            if (cache.Count >= 128) cache.Clear();
            if (result.Ttl > 0) cache[host] = (result.Address, DateTimeOffset.UtcNow.AddSeconds(Math.Min(result.Ttl, 60)));
            return result.Address;
        }
        finally { requests.Release(); }
    }
    internal static (IPAddress Address, int Ttl) Parse(string host, byte[] body)
    {
        using var doc = JsonDocument.Parse(body); var root = doc.RootElement;
        if (root.GetProperty("Status").GetInt32() != 0 || root.TryGetProperty("TC", out var tc) && tc.GetBoolean()) throw new IOException("DohLookupRejected");
        var question = root.GetProperty("Question");
        if (question.GetArrayLength() != 1 || question[0].GetProperty("type").GetInt32() != 1 ||
            !question[0].GetProperty("name").GetString()!.TrimEnd('.').Equals(host.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)) throw new IOException("DohQuestionMismatch");
        var answers = root.GetProperty("Answer"); if (answers.GetArrayLength() > 256) throw new IOException("DohAnswerLimit");
        string current = host.TrimEnd('.');
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current };
        int ttl = int.MaxValue;
        for (int i = 0; i < 32; i++)
        {
            var aliases = answers.EnumerateArray().Where(a => a.GetProperty("type").GetInt32() == 5 &&
                a.GetProperty("name").GetString()!.TrimEnd('.').Equals(current, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (aliases.Length == 0) break;
            if (aliases.Length != 1 || i == 31 || answers.EnumerateArray().Any(a => a.GetProperty("type").GetInt32() == 1 && a.GetProperty("name").GetString()!.TrimEnd('.').Equals(current, StringComparison.OrdinalIgnoreCase)))
                throw new IOException("DohAmbiguousCname");
            string name = aliases[0].GetProperty("data").GetString()!.TrimEnd('.');
            if (Uri.CheckHostName(name) != UriHostNameType.Dns || !names.Add(name)) throw new IOException("DohInvalidCname");
            ttl = Math.Min(ttl, aliases[0].TryGetProperty("TTL", out var time) ? time.GetInt32() : 0);
            current = name;
        }
        foreach (var answer in answers.EnumerateArray())
            if (answer.GetProperty("type").GetInt32() == 1 && answer.GetProperty("name").GetString()!.TrimEnd('.').Equals(current, StringComparison.OrdinalIgnoreCase) &&
                IPAddress.TryParse(answer.GetProperty("data").GetString(), out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
                PathFlux.Application.ExperimentalUdpPolicy.IsUnicast(ip))
                return (ip, Math.Max(0, Math.Min(ttl, answer.TryGetProperty("TTL", out var time) ? time.GetInt32() : 0)));
        throw new IOException("DohNoIPv4Answer");
    }
    public void Dispose() { client.Dispose(); requests.Dispose(); }
}
