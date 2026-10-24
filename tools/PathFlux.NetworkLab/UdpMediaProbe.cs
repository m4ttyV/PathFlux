using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace PathFlux.NetworkLab;

/// <summary>Bounded synthetic screen-share load, not a Discord compatibility claim.
/// 60,000 x 1,200 byte packets, batches of 20 every 20ms; validates every received byte.</summary>
public static class UdpMediaProbe
{
    public static async Task<ProbeResult> RunAsync(string host, int port, CancellationToken ct)
    {
        const int count = 60000, size = 1200;
        using var client = new UdpClient(AddressFamily.InterNetwork); client.Client.ReceiveBufferSize = 1024 * 1024;
        client.Connect(IPAddress.Parse(host), port);
        var template = RandomNumberGenerator.GetBytes(size);
        var seen = new bool[count]; var sentAt = new long[count];
        int received = 0, invalid = 0;
        using var receiveStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var receive = Task.Run(async () =>
        {
            try
            {
                while (!receiveStop.IsCancellationRequested)
                {
                    var packet = (await client.ReceiveAsync(receiveStop.Token)).Buffer;
                    if (packet.Length != size || !packet.AsSpan(4).SequenceEqual(template.AsSpan(4))) { invalid++; continue; }
                    int index = BinaryPrimitives.ReadInt32BigEndian(packet);
                    if (index < 0 || index >= count || Volatile.Read(ref sentAt[index]) == 0 || seen[index]) { invalid++; continue; }
                    seen[index] = true; Interlocked.Increment(ref received);
                }
            }
            catch (OperationCanceledException) when (receiveStop.IsCancellationRequested) { }
        }, ct);
        var elapsed = Stopwatch.StartNew();
        int sent = 0;
        try
        {
            while (sent < count)
            {
                for (int i = 0; i < 20 && sent < count; i++, sent++)
                {
                    var packet = template.ToArray(); BinaryPrimitives.WriteInt32BigEndian(packet, sent);
                    Volatile.Write(ref sentAt[sent], Stopwatch.GetTimestamp()); await client.SendAsync(packet, ct);
                }
                await Task.Delay(20, ct);
            }
            await Task.Delay(2000, ct);
        }
        finally { receiveStop.Cancel(); await receive; }
        return new(received >= 59400 && invalid == 0, $"SyntheticMedia1200Bytes;Invalid={invalid};DurationMs={elapsed.ElapsedMilliseconds}", sent, received);
    }
}
