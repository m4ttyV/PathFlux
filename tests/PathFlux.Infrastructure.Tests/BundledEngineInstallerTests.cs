using PathFlux.Infrastructure;

namespace PathFlux.Infrastructure.Tests;

public sealed class BundledEngineInstallerTests
{
    [Fact]
    public async Task MissingSourcePackageCannotBeInstalled()
    {
        var root = Path.Combine(Path.GetTempPath(), "PathFlux-installer-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(Path.Combine(root, "sing-box.exe"), "not an executable");
            var error = await Assert.ThrowsAsync<InvalidOperationException>(() => new BundledEngineInstaller(root, Path.Combine(root, "installed")).InstallAsync(default));
            Assert.Contains("полного пакета", error.Message);
            Assert.False(Directory.Exists(Path.Combine(root, "installed")));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public async Task CorruptBinaryIsNeverExecutedOrReplacesAnExistingEngineAndTemporaryCopyIsRemoved()
    {
        var root = Path.Combine(Path.GetTempPath(), "PathFlux-installer-" + Guid.NewGuid().ToString("N"));
        try
        {
            var package = Path.Combine(root, "package"); Directory.CreateDirectory(package);
            foreach (var name in new[] { "sing-box.exe", "source.zip", "LICENSE.sing-box", "build-manifest.json" })
                await File.WriteAllTextAsync(Path.Combine(package, name), "tampered package");
            var installRoot = Path.Combine(root, "installed");
            var versionDirectory = Path.Combine(installRoot, BundledEngineInstaller.EngineSha256.ToLowerInvariant());
            Directory.CreateDirectory(versionDirectory);
            var old = Path.Combine(versionDirectory, "sing-box.exe"); await File.WriteAllTextAsync(old, "keep existing");
            await Assert.ThrowsAsync<InvalidOperationException>(() => new BundledEngineInstaller(package, installRoot).InstallAsync(default));
            Assert.Equal("keep existing", await File.ReadAllTextAsync(old));
            Assert.Empty(Directory.GetFiles(versionDirectory, "*.tmp"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }
}
