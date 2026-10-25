using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
namespace PathFlux.Engine;

public static class EngineBinary
{
    public static void EnsurePath(string path)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Движок поддерживается только в Windows.");
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) || !string.Equals(Path.GetFileName(path), "sing-box.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Укажите полный путь к официальному sing-box.exe.");
    }
    public static readonly Version MinimumVersion = new(1, 12, 2);
    internal static async Task VerifyProcessTreeBackendAsync(string path, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(5));
        var info = new ProcessStartInfo(path) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        info.ArgumentList.Add("pathflux-capabilities");
        using var child = Process.Start(info) ?? throw new InvalidOperationException("Не удалось проверить backend дерева PID.");
        try
        {
            var stdout = ReadBoundedAsync(child.StandardOutput, deadline.Token);
            var stderr = child.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await child.WaitForExitAsync(deadline.Token); await stderr;
            if (child.ExitCode != 0) throw new InvalidOperationException("Для дерева PID требуется отдельная сборка PathFlux Process Tree; официальный sing-box её не поддерживает.");
            using var document = System.Text.Json.JsonDocument.Parse(await stdout);
            var r = document.RootElement;
            if (r.GetProperty("protocol").GetInt32() != 3 || !r.GetProperty("decisionSnapshot").GetBoolean() || !r.GetProperty("processSequenceNumber").GetBoolean() || !r.GetProperty("processTree").GetBoolean() ||
                !r.GetProperty("pidCreationTime").GetBoolean() || !r.GetProperty("udpOwnerGuard").GetBoolean())
                throw new InvalidOperationException("Backend не подтвердил обязательные возможности дерева PID.");
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); } }
    }
    public static Version ParseVersion(string output)
    {
        var match = Regex.Match(output, @"\Asing-box version (0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z.-]+)?\r?(?:\n|\z)", RegexOptions.CultureInvariant);
        if (!match.Success || !Version.TryParse($"{match.Groups[1]}.{match.Groups[2]}.{match.Groups[3]}", out var version))
            throw new InvalidOperationException("Не удалось определить версию sing-box.");
        if (version < MinimumVersion || (version == MinimumVersion && match.Groups[4].Success))
            throw new InvalidOperationException("Требуется sing-box версии 1.12.2 или новее.");
        return version;
    }
    public static async Task<Version> VerifyAsync(string path, string expectedHash, CancellationToken ct)
    {
        EnsurePath(path);
        if (expectedHash is null || expectedHash.Length != 64 || !expectedHash.All(char.IsAsciiHexDigit))
            throw new InvalidOperationException("Укажите SHA-256 выбранного sing-box.exe: 64 шестнадцатеричных символа.");
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
        if (!string.Equals(hash, expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Контрольная сумма движка не совпадает. Запуск отклонён.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var info = new ProcessStartInfo(path) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, WorkingDirectory = AppContext.BaseDirectory };
        info.ArgumentList.Add("version");
        using var process = Process.Start(info) ?? throw new InvalidOperationException("Не удалось проверить версию sing-box.");
        try
        {
            var stdout = ReadBoundedAsync(process.StandardOutput, deadline.Token);
            var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null, deadline.Token);
            await process.WaitForExitAsync(deadline.Token); await stderr;
            var output = await stdout;
            if (process.ExitCode != 0) throw new InvalidOperationException("sing-box version завершился с ошибкой.");
            var version = ParseVersion(output);
            if (!Regex.IsMatch(output, @"(?m)^Environment: [^\r\n]* windows/amd64\r?$", RegexOptions.CultureInvariant))
                throw new InvalidOperationException("Требуется сборка sing-box для Windows x64 (windows/amd64).");
            return version;
        }
        finally { if (!process.HasExited) { process.Kill(true); await process.WaitForExitAsync(CancellationToken.None); } }
    }
    private static async Task<string> ReadBoundedAsync(StreamReader reader, CancellationToken ct)
    {
        var output = new StringBuilder(); var buffer = new char[512];
        int count;
        while ((count = await reader.ReadAsync(buffer.AsMemory(), ct)) != 0)
        {
            if (output.Length + count > 4096) throw new InvalidOperationException("Некорректный ответ sing-box version.");
            output.Append(buffer, 0, count);
        }
        return output.ToString();
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
