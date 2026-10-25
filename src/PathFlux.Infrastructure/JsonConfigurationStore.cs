using System.Text.Json;
using System.Text.Json.Serialization;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

/// <summary>Versioned local configuration, with atomic replacement and a last-valid backup.</summary>
public sealed class JsonConfigurationStore(string path) : IConfigurationStore, ISecretReferenceRetention
{
    private const int CurrentSchema = 2;
    private readonly string _path = Path.GetFullPath(path);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };

    public async Task<ProxyConfiguration> LoadAsync(CancellationToken ct)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_path) && !File.Exists(_path + ".bak")) return new();
            try { return await ReadAsync(_path, ct).ConfigureAwait(false); }
            catch (InvalidDataException) when (File.Exists(_path + ".bak"))
            {
                return await ReadAsync(_path + ".bak", ct).ConfigureAwait(false);
            }
            catch (FileNotFoundException) when (File.Exists(_path + ".bak"))
            {
                return await ReadAsync(_path + ".bak", ct).ConfigureAwait(false);
            }
        }
        finally { _gate.Release(); }
    }

    public async Task SaveAsync(ProxyConfiguration configuration, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        if (configuration.SchemaVersion != CurrentSchema)
            throw new NotSupportedException("Unsupported configuration schema. The original file is preserved.");
        ValidateStructure(configuration);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        string? temporary = null;
        try
        {
            // Refuse to overwrite future schema data, including its recovery copy.
            var primaryIsValid = false;
            if (File.Exists(_path))
            {
                try { await ReadAsync(_path, ct).ConfigureAwait(false); primaryIsValid = true; }
                catch (InvalidDataException) { }
            }
            if (File.Exists(_path + ".bak"))
            {
                try { await ReadAsync(_path + ".bak", ct).ConfigureAwait(false); }
                catch (InvalidDataException) { }
            }
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, configuration, Options, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }
            ct.ThrowIfCancellationRequested();
            if (primaryIsValid)
                File.Replace(temporary, _path, _path + ".bak", ignoreMetadataErrors: false);
            else
            {
                if (File.Exists(_path))
                    File.Copy(_path, _path + ".corrupt-" + Guid.NewGuid().ToString("N"), overwrite: false);
                File.Move(temporary, _path, overwrite: true);
            }
            temporary = null;
        }
        finally
        {
            if (temporary is not null)
            {
                try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            _gate.Release();
        }
    }

    public async Task<bool> IsReferencedAsync(string reference, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(reference);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path)!;
            // A damaged archive may contain a reference that is no longer readable. Retain secrets
            // conservatively until the user resolves/removes recovery files; never guess from text.
            var files = new[] { _path, _path + ".bak" }
                .Concat(Directory.EnumerateFiles(directory, Path.GetFileName(_path) + ".corrupt-*"));
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ProxyConfiguration configuration;
                try { configuration = await ReadAsync(file, ct).ConfigureAwait(false); }
                catch (FileNotFoundException) { continue; }
                if (configuration.Profiles.Any(p => string.Equals(p.CredentialsRef, reference, StringComparison.Ordinal))) return true;
            }
            return false;
        }
        catch (DirectoryNotFoundException) { return false; }
        catch (Exception exception) when (exception is InvalidDataException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return true;
        }
        finally { _gate.Release(); }
    }

    private static async Task<ProxyConfiguration> ReadAsync(string file, CancellationToken ct)
    {
        try
        {
            await using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("schemaVersion", out var schema) || schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var version))
                throw new InvalidDataException("Configuration has no valid schema version. Original data is preserved.");
            if (version > CurrentSchema)
                throw new NotSupportedException("Configuration was created by a newer version. Original data is preserved.");
            if (version is not (1 or CurrentSchema))
                throw new InvalidDataException("Unsupported legacy configuration schema. Original data is preserved.");
            var configuration = document.Deserialize<ProxyConfiguration>(Options)
                ?? throw new InvalidDataException("Configuration is empty. Original data is preserved.");
            ValidateStructure(configuration);
            if (version == 1) configuration = configuration with { SchemaVersion = CurrentSchema,
                Settings = configuration.Settings with { ExperimentalSocksUdp = false, ExperimentalProcessTrees = false },
                Profiles = configuration.Profiles.Select(p => p with { UdpRelayMode = UdpRelayMode.Standard, UdpPublishedPortFirst = null, UdpPublishedPortLast = null, UseTlsServerNameForTcp = false }).ToList() };
            return configuration;
        }
        catch (JsonException)
        {
            // Do not put JSON fragments or user data in error messages.
            throw new InvalidDataException("Configuration is malformed. Original data is preserved.");
        }
    }

    private static void ValidateStructure(ProxyConfiguration configuration)
    {
        if (configuration.Profiles is null || configuration.Rules is null || configuration.Settings is null ||
            configuration.Profiles.Any(p => p is null) || configuration.Rules.Any(r => r is null || r.Selector is null))
            throw new InvalidDataException("Configuration contains missing required values. Original data is preserved.");
    }
}
