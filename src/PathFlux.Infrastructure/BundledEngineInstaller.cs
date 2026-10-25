using System.Security.Cryptography;
using PathFlux.Application;

namespace PathFlux.Infrastructure;

/// <summary>Installs the pinned, source-accompanied PathFlux engine without elevation or network access.</summary>
public sealed class BundledEngineInstaller(string packageDirectory, string installationDirectory) : IEngineInstaller
{
    public const string EngineSha256 = "3149B341FC2AC1F8E383C6A54C5DD3E4BF2E0DEE8901C8A435903A08C0594C81";
    public async Task<EngineInstallation> InstallAsync(CancellationToken ct)
    {
        var source = Path.Combine(packageDirectory, "sing-box.exe");
        string[] accompanying = ["LICENSE.sing-box", "source.zip", "build-manifest.json"];
        if (!File.Exists(source) || accompanying.Any(name => !File.Exists(Path.Combine(packageDirectory, name))))
            throw new InvalidOperationException("В этой сборке нет полного пакета движка. Скачайте portable-папку PathFlux целиком, включая engine-package.");
        var destination = Path.Combine(installationDirectory, EngineSha256.ToLowerInvariant());
        Directory.CreateDirectory(destination);
        // Immutable versioned destination; a working configured engine is never overwritten.
        var final = Path.Combine(destination, "sing-box.exe");
        var temporary = Path.Combine(destination, Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            await using (var input = File.OpenRead(source))
            await using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await input.CopyToAsync(output, ct);
            if (await HashAsync(temporary, ct) != EngineSha256)
                throw new InvalidOperationException("Проверка пакета движка не пройдена. Настройки не изменены; получите полную сборку PathFlux заново.");
            foreach (var name in accompanying)
            {
                ct.ThrowIfCancellationRequested();
                File.Copy(Path.Combine(packageDirectory, name), Path.Combine(destination, name), true);
            }
            if (File.Exists(final))
            {
                if (await HashAsync(final, ct) != EngineSha256)
                    throw new InvalidOperationException("Установленный движок изменён. Укажите другой каталог установки или восстановите пакет.");
            }
            else File.Move(temporary, final);
            return new(final, EngineSha256);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    private static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
    }
}
