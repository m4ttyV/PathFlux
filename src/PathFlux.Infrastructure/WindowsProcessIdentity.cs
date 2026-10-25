using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace PathFlux.Infrastructure;

internal static class WindowsProcessIdentity
{
    internal sealed record Snapshot(DateTimeOffset StartedUtc, ulong SequenceNumber, int? ParentPid);
    internal static Snapshot? Read(int pid)
    {
        if (!OperatingSystem.IsWindows() || pid <= 4) return null;
        using var handle = OpenProcess(0x1000, false, pid);
        if (handle.IsInvalid || !GetProcessTimes(handle, out ulong created, out ulong exited, out _, out _) || exited != 0 || created > long.MaxValue) return null;
        // ProcessSequenceNumber is a system instance counter, independent of UTC corrections.
        if (NtQuerySequence(handle, 92, out ulong sequence, sizeof(ulong), IntPtr.Zero) != 0 || sequence == 0) return null;
        int? parent = null;
        if (NtQueryBasic(handle, 0, out var basic, Marshal.SizeOf<BasicInformation>(), IntPtr.Zero) == 0 && basic.ParentId.ToInt64() is >= 0 and <= int.MaxValue)
            parent = (int)basic.ParentId.ToInt64();
        try { return new(new DateTimeOffset(DateTime.FromFileTimeUtc((long)created)), sequence, parent); }
        catch (ArgumentOutOfRangeException) { return null; }
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicInformation
    { public IntPtr ExitStatus, Peb, Affinity, BasePriority, ProcessId, ParentId; }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out ulong created, out ulong exited, out ulong kernel, out ulong user);
    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQuerySequence(SafeProcessHandle process, int infoClass, out ulong value, int size, IntPtr returned);
    [DllImport("ntdll.dll", EntryPoint = "NtQueryInformationProcess")]
    private static extern int NtQueryBasic(SafeProcessHandle process, int infoClass, out BasicInformation value, int size, IntPtr returned);
}
