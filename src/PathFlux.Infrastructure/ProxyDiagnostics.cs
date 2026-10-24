using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

/// <summary>Active proxy handshakes. A successful CONNECT proves a tunnel was accepted, not application traffic interception.</summary>
public sealed class ProxyDiagnostics(ISecretStore secrets, TimeSpan? timeout = null) : IProxyDiagnostics
{
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(15);

    public Task<DiagnosticResult> TestTcpAsync(ProxyProfile profile, string targetHost, int targetPort, CancellationToken ct) =>
        RunAsync(profile, targetHost, targetPort, udp: false, ct);

    public Task<DiagnosticResult> TestUdpAssociateAsync(ProxyProfile profile, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (profile.Protocol != ProxyProtocol.Socks5)
            return Task.FromResult(new DiagnosticResult(false, "udp", "HTTP CONNECT не поддерживает UDP ASSOCIATE.", SupportStatus.Unsupported));
        return RunAsync(profile, "0.0.0.0", 0, udp: true, ct);
    }

    private async Task<DiagnosticResult> RunAsync(ProxyProfile profile, string targetHost, int targetPort, bool udp, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(_timeout);
        var stage = "validation";
        try
        {
            var proxyHost = NormalizeHost(profile.Host);
            var host = NormalizeHost(targetHost);
            if (profile.Port is < 1 or > 65535 || targetPort is < 0 or > 65535 || (!udp && targetPort == 0))
                throw new ProbeException("validation", "Некорректный номер порта.");
            if (!Enum.IsDefined(profile.Protocol))
                throw new ProbeException("validation", "Протокол прокси не поддерживается.");
            ProxyCredentials? credentials = null;
            if (profile.CredentialsRef is not null)
            {
                stage = "credentials";
                credentials = await secrets.GetAsync(profile.CredentialsRef, deadline.Token).ConfigureAwait(false)
                    ?? throw new ProbeException(stage, "Сохранённые учётные данные не найдены.");
            }
            stage = "tcp";
            using var client = new TcpClient();
            await client.ConnectAsync(proxyHost, profile.Port, deadline.Token).ConfigureAwait(false);
            Stream stream = client.GetStream();
            if (profile.Protocol == ProxyProtocol.HttpsConnect)
            {
                stage = "tls";
                var tls = new SslStream(stream, leaveInnerStreamOpen: false);
                stream = tls;
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = NormalizeHost(profile.TlsServerName ?? proxyHost),
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online
                }, deadline.Token).ConfigureAwait(false);
            }
            await using (stream.ConfigureAwait(false))
            {
                stage = "proxy";
                if (profile.Protocol == ProxyProtocol.Socks5)
                    await ProbeSocksAsync(stream, host, targetPort, udp, credentials, deadline.Token).ConfigureAwait(false);
                else
                    await ProbeHttpAsync(stream, host, targetPort, credentials, deadline.Token).ConfigureAwait(false);
            }
            return udp
                ? new DiagnosticResult(true, "udp-associate", "UDP ASSOCIATE принят. Передача UDP через relay ещё не проверена.", SupportStatus.NotVerified)
                : new DiagnosticResult(true, "connect", "Прокси подтвердил TCP CONNECT к выбранной цели. Маршрутизация приложений этим тестом не проверяется.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return Failure(udp, stage, "Истекло время ожидания проверки."); }
        catch (ProbeException exception)
        { return Failure(udp, exception.Stage, exception.SafeMessage, exception.UdpStatus); }
        catch (AuthenticationException)
        { return Failure(udp, "tls", "Проверка TLS-сертификата или установка защищённого соединения не удалась."); }
        catch (SocketException)
        { return Failure(udp, "tcp", "Не удалось подключиться к прокси или соединение было разорвано."); }
        catch (IOException)
        { return Failure(udp, stage, "Прокси закрыл соединение или прислал неполный ответ."); }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or UnauthorizedAccessException or NotSupportedException)
        { return Failure(udp, stage, "Параметры проверки или защищённые учётные данные недоступны."); }
    }

    private static DiagnosticResult Failure(bool udp, string stage, string message, SupportStatus? udpStatus = null) =>
        new(false, stage, message, udp ? udpStatus ?? SupportStatus.Failed : SupportStatus.NotVerified);

    private static async Task ProbeSocksAsync(Stream stream, string host, int port, bool udp, ProxyCredentials? credentials, CancellationToken ct)
    {
        var method = credentials is null ? (byte)0 : (byte)2;
        await stream.WriteAsync(new byte[] { 5, 1, method }, ct).ConfigureAwait(false);
        var selection = new byte[2];
        await stream.ReadExactlyAsync(selection, ct).ConfigureAwait(false);
        if (selection[0] != 5) throw new ProbeException("socks", "Ответ не соответствует SOCKS5.");
        if (selection[1] != method) throw new ProbeException("authentication", "SOCKS5 не принял выбранный метод аутентификации.");
        if (credentials is not null)
        {
            var username = Encoding.UTF8.GetBytes(credentials.Username);
            var password = Encoding.UTF8.GetBytes(credentials.Password);
            byte[]? request = null;
            try
            {
                if (username.Length is < 1 or > 255 || password.Length is < 1 or > 255)
                    throw new ProbeException("authentication", "SOCKS5 требует логин и пароль длиной от 1 до 255 байт UTF-8.");
                request = new byte[3 + username.Length + password.Length];
                request[0] = 1;
                request[1] = (byte)username.Length;
                username.CopyTo(request, 2);
                request[username.Length + 2] = (byte)password.Length;
                password.CopyTo(request, username.Length + 3);
                await stream.WriteAsync(request, ct).ConfigureAwait(false);
                await stream.ReadExactlyAsync(selection, ct).ConfigureAwait(false);
                if (selection[0] != 1 || selection[1] != 0)
                    throw new ProbeException("authentication", "SOCKS5 отклонил учётные данные.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(username);
                CryptographicOperations.ZeroMemory(password);
                if (request is not null) CryptographicOperations.ZeroMemory(request);
            }
        }

        byte[] address;
        byte addressType;
        if (IPAddress.TryParse(host, out var ip))
        {
            address = ip.GetAddressBytes();
            addressType = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
        }
        else
        {
            var domain = Encoding.ASCII.GetBytes(host);
            if (domain.Length > 255) throw new ProbeException("validation", "Имя цели слишком длинное для SOCKS5.");
            address = new byte[domain.Length + 1];
            address[0] = (byte)domain.Length;
            domain.CopyTo(address, 1);
            addressType = 3;
        }
        var command = new byte[6 + address.Length];
        command[0] = 5;
        command[1] = udp ? (byte)3 : (byte)1;
        command[3] = addressType;
        address.CopyTo(command, 4);
        command[^2] = (byte)(port >> 8);
        command[^1] = (byte)port;
        await stream.WriteAsync(command, ct).ConfigureAwait(false);
        var response = new byte[4];
        await stream.ReadExactlyAsync(response, ct).ConfigureAwait(false);
        if (response[0] != 5 || response[2] != 0)
            throw new ProbeException("socks", "Некорректный ответ SOCKS5.");
        if (response[1] != 0)
            throw new ProbeException(udp ? "udp-associate" : "connect", SocksFailure(response[1]),
                udp && response[1] == 7 ? SupportStatus.Unsupported : null);
        var length = response[3] switch
        {
            1 => 4,
            4 => 16,
            3 => await ReadDomainLengthAsync(stream, ct).ConfigureAwait(false),
            _ => throw new ProbeException("socks", "SOCKS5 вернул неизвестный тип адреса.")
        };
        await stream.ReadExactlyAsync(new byte[length + 2], ct).ConfigureAwait(false);
    }

    private static async Task<int> ReadDomainLengthAsync(Stream stream, CancellationToken ct)
    {
        var size = new byte[1];
        await stream.ReadExactlyAsync(size, ct).ConfigureAwait(false);
        if (size[0] == 0) throw new ProbeException("socks", "SOCKS5 вернул пустой адрес.");
        return size[0];
    }

    private static string SocksFailure(byte status) => status switch
    {
        2 => "SOCKS5 запретил запрос политикой сервера.",
        3 => "SOCKS5 сообщил о недоступности сети цели.",
        4 => "SOCKS5 сообщил о недоступности узла цели.",
        5 => "Цель отклонила соединение через SOCKS5.",
        7 => "SOCKS5 не поддерживает запрошенную команду.",
        8 => "SOCKS5 не поддерживает тип адреса цели.",
        _ => "SOCKS5 отклонил запрос."
    };

    private static async Task ProbeHttpAsync(Stream stream, string host, int port, ProxyCredentials? credentials, CancellationToken ct)
    {
        var authority = IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{host}]:{port}" : $"{host}:{port}";
        var header = $"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n";
        if (credentials is not null)
        {
            if (credentials.Username.Contains(':') || credentials.Username.Contains('\r') || credentials.Username.Contains('\n'))
                throw new ProbeException("authentication", "Недопустимый формат имени пользователя HTTP Basic.");
            var credentialBytes = Encoding.UTF8.GetBytes(credentials.Username + ":" + credentials.Password);
            try { header += "Proxy-Authorization: Basic " + Convert.ToBase64String(credentialBytes) + "\r\n"; }
            finally { CryptographicOperations.ZeroMemory(credentialBytes); }
        }
        var request = Encoding.ASCII.GetBytes(header + "\r\n");
        try { await stream.WriteAsync(request, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(request); }
        // Read only through the header boundary: subsequent tunnel data belongs to the target.
        for (var interim = 0; interim < 5; interim++)
        {
            var response = new List<byte>();
            var single = new byte[1];
            while (response.Count < 16384)
            {
                await stream.ReadExactlyAsync(single, ct).ConfigureAwait(false);
                response.Add(single[0]);
                if (response.Count >= 4 && response[^4] == 13 && response[^3] == 10 && response[^2] == 13 && response[^1] == 10) break;
            }
            if (response.Count >= 16384) throw new ProbeException("http", "Заголовки HTTP-прокси превышают допустимый размер.");
            var firstLine = Encoding.ASCII.GetString(response.ToArray()).Split("\r\n", 2)[0];
            var parts = firstLine.Split(' ', 3);
            if (parts.Length < 2 || parts[0] is not ("HTTP/1.0" or "HTTP/1.1") || parts[1].Length != 3 ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var status))
                throw new ProbeException("http", "Прокси вернул некорректный HTTP-ответ.");
            if (status is >= 200 and < 300) return;
            if (status is >= 100 and < 200 && status != 101) continue;
            if (status == 407) throw new ProbeException("authentication", "HTTP-прокси отклонил аутентификацию.");
            throw new ProbeException("connect", "HTTP-прокси отклонил CONNECT.");
        }
        throw new ProbeException("http", "HTTP-прокси не завершил ответ на CONNECT.");
    }

    private static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || host.IndexOfAny(['/', '\\', '@', '#', '?']) >= 0)
            throw new ProbeException("validation", "Некорректное имя узла.");
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return ip.ToString();
        var normalized = new IdnMapping().GetAscii(host);
        if (Uri.CheckHostName(normalized) != UriHostNameType.Dns)
            throw new ProbeException("validation", "Некорректное имя узла.");
        return normalized;
    }

    private sealed class ProbeException(string stage, string safeMessage, SupportStatus? udpStatus = null) : Exception(safeMessage)
    {
        public string Stage { get; } = stage;
        public string SafeMessage { get; } = safeMessage;
        public SupportStatus? UdpStatus { get; } = udpStatus;
    }
}
