using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using PathFlux.Application;
using PathFlux.Domain;

namespace PathFlux.Infrastructure;

/// <summary>Opaque references to Windows DPAPI data protected for the current Windows user.</summary>
public sealed class DpapiSecretStore(string directory) : ISecretStore
{
    private readonly string _directory = Path.GetFullPath(directory);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<string> StoreAsync(ProxyCredentials credentials, CancellationToken ct)
    {
        EnsureWindows();
        ArgumentNullException.ThrowIfNull(credentials);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        var clear = JsonSerializer.SerializeToUtf8Bytes(credentials);
        byte[]? protectedBytes = null;
        string? temporary = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            protectedBytes = Protect(clear, encrypt: true);
            var reference = Guid.NewGuid().ToString("N");
            Directory.CreateDirectory(_directory);
            var destination = GetPath(reference);
            temporary = destination + ".tmp";
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await stream.WriteAsync(protectedBytes, ct).ConfigureAwait(false);
                await stream.FlushAsync(ct).ConfigureAwait(false);
                stream.Flush(true);
            }
            ct.ThrowIfCancellationRequested();
            File.Move(temporary, destination);
            temporary = null;
            return reference;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (temporary is not null)
            {
                try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            _gate.Release();
        }
    }

    public async Task<ProxyCredentials?> GetAsync(string reference, CancellationToken ct)
    {
        EnsureWindows();
        var file = GetPath(reference);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        byte[]? clear = null;
        try
        {
            byte[] encrypted;
            try { encrypted = await File.ReadAllBytesAsync(file, ct).ConfigureAwait(false); }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
            clear = Protect(encrypted, encrypt: false);
            try
            {
                var credentials = JsonSerializer.Deserialize<ProxyCredentials>(clear);
                if (credentials?.Username is null || credentials.Password is null)
                    throw new CryptographicException("Stored credentials are invalid.");
                return credentials;
            }
            catch (JsonException) { throw new CryptographicException("Stored credentials are invalid."); }
        }
        finally
        {
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
            _gate.Release();
        }
    }

    public async Task DeleteAsync(string reference, CancellationToken ct)
    {
        EnsureWindows();
        var file = GetPath(reference);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try { ct.ThrowIfCancellationRequested(); File.Delete(file); }
        finally { _gate.Release(); }
    }

    private string GetPath(string reference)
    {
        if (reference is null || !Guid.TryParseExact(reference, "N", out var id) || id == Guid.Empty)
            throw new ArgumentException("Invalid secret reference.", nameof(reference));
        return Path.Combine(_directory, id.ToString("N") + ".bin");
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows DPAPI is required for credential storage.");
    }

    private static byte[] Protect(byte[] data, bool encrypt)
    {
        var input = new DataBlob { Length = data.Length, Data = Marshal.AllocHGlobal(data.Length) };
        DataBlob output = default;
        try
        {
            Marshal.Copy(data, 0, input.Data, data.Length);
            var success = encrypt
                ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            // CRYPTPROTECT_UI_FORBIDDEN; deliberately no CRYPTPROTECT_LOCAL_MACHINE.
            if (!success) throw new CryptographicException("Windows DPAPI could not protect or read the credential.");
            var result = new byte[output.Length];
            Marshal.Copy(output.Data, result, 0, output.Length);
            return result;
        }
        finally
        {
            ClearNative(input.Data, input.Length);
            Marshal.FreeHGlobal(input.Data);
            if (output.Data != IntPtr.Zero)
            {
                ClearNative(output.Data, output.Length);
                LocalFree(output.Data);
            }
        }
    }

    private static void ClearNative(IntPtr pointer, int length)
    {
        for (var index = 0; index < length; index++) Marshal.WriteByte(pointer, index, 0);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, string? description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
