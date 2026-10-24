using System.Buffers.Binary;
using System.Text.Json;
using PathFlux.Domain;
namespace PathFlux.Engine;

public sealed record AgentRequest(string Operation, ProxyConfiguration? Configuration = null, Dictionary<string, ProxyCredentials>? Credentials = null);
public sealed record AgentReply(bool Success, EngineStatus Status);
public static class AgentProtocol
{
    public const int MaxMessageBytes = 1_048_576;
    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length > MaxMessageBytes) throw new InvalidDataException("Слишком большой запрос агента.");
        var prefix = new byte[4]; BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
        await stream.WriteAsync(prefix, ct); await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct);
    }
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken ct)
    {
        var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, ct);
        int size = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (size is <= 0 or > MaxMessageBytes) throw new InvalidDataException("Некорректный размер сообщения агента.");
        var bytes = new byte[size]; await stream.ReadExactlyAsync(bytes, ct);
        return JsonSerializer.Deserialize<T>(bytes) ?? throw new InvalidDataException("Некорректное сообщение агента.");
    }
}
