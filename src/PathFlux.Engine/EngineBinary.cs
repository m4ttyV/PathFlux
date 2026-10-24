using System.Diagnostics;
using System.Security.Cryptography;
namespace PathFlux.Engine;

public static class EngineBinary
{
    // Official v1.12.12 Windows amd64 archive digest checked against GitHub release asset API.
    public const string ArchiveSha256 = "352c69526b76cd199539c0e02b4042d1acc109cde3a0a671a40af4e24290faa4";
    public const string ExecutableSha256 = "f1e6453b62482a95c9461d2c84d8e1a95567609f739adf6a1227a9b96c578747";
    public static void EnsurePath(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Движок поддерживается только в Windows.");
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) || !string.Equals(Path.GetFileName(path), "sing-box.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Укажите полный путь к официальному sing-box.exe.");
    }
    public static async Task VerifyAsync(string path, string expectedHash, CancellationToken ct)
    {
        EnsurePath(path);
        if (!string.Equals(expectedHash, ExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("SHA-256 должен совпадать с закреплённым официальным sing-box 1.12.12 Windows x64.");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
        if (!string.Equals(hash, ExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Контрольная сумма движка не совпадает. Запуск отклонён.");
    }
    public static ProcessStartInfo CreateStartInfo(string path, string command)
    {
        var info = new ProcessStartInfo(path) { UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory };
        info.ArgumentList.Add(command); info.ArgumentList.Add("-c"); info.ArgumentList.Add("stdin");
        return info;
    }
    public static async Task<bool> CheckAsync(string path, string json, CancellationToken ct)
    {
        using var process = new Process { StartInfo = CreateStartInfo(path, "check") };
        process.Start();
        try
        {
            // Raw diagnostics can contain credentials. Drain and discard, return only structured status.
            var stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null, ct);
            var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, ct);
            await process.StandardInput.WriteAsync(json.AsMemory(), ct); process.StandardInput.Close();
            await process.WaitForExitAsync(ct); await Task.WhenAll(stdout, stderr);
            return process.ExitCode == 0;
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
}
