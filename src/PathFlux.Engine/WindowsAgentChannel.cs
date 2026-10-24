using System.IO.Pipes;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace PathFlux.Engine;

/// <summary>User-SID restricted IPC that works across UAC token owner changes.</summary>
public static class WindowsAgentChannel
{
    public static NamedPipeServerStream CreateServer(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        var user = identity.User ?? throw new UnauthorizedAccessException();
        var security = new PipeSecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(user);
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
        // CurrentUserOnly in .NET 10 compares token Owner, which changes on UAC elevation.
        // Explicit DACL uses User instead. FirstPipeInstance prevents taking over an existing name.
        return NamedPipeServerStreamAcl.Create(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance, 0, 0, security);
    }

    public static ProcessStartInfo CreateStartInfo(string agentPath, string pipeName)
    {
        var info = new ProcessStartInfo(agentPath) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = Path.GetDirectoryName(agentPath)! };
        info.ArgumentList.Add("--pipe"); info.ArgumentList.Add(pipeName);
        info.ArgumentList.Add("--parent"); info.ArgumentList.Add(Environment.ProcessId.ToString());
        using var current = Process.GetCurrentProcess();
        info.ArgumentList.Add("--started"); info.ArgumentList.Add(current.StartTime.ToUniversalTime().Ticks.ToString());
        return info;
    }

    public static NamedPipeClientStream CreateClient(string name)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        // Do not permit the UI pipe server to impersonate the elevated agent.
        return new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Anonymous, HandleInheritability.None);
    }

    public static void VerifyServer(NamedPipeClientStream pipe, int expectedPid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint actualPid) || actualPid != expectedPid ||
            pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || owner != identity.User)
            throw new UnauthorizedAccessException("Не удалось подтвердить пользователя и процесс UI.");
    }

    public static void VerifyClient(NamedPipeServerStream pipe, int expectedPid)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint actualPid) || actualPid != expectedPid)
            throw new UnauthorizedAccessException("Не удалось подтвердить процесс сетевого агента.");
    }

    public static string DescribeExit(int code) => code switch
    {
        2 => "Агент отклонил параметры запуска. Обновите приложение вместе с папкой agent.",
        3 => "Агент не получил права администратора. Подтвердите запрос UAC под той же учётной записью Windows.",
        4 => "Другой сетевой агент PathFlux уже работает. Остановите предыдущую сессию.",
        5 => "Агент не подтвердил запустивший его процесс UI.",
        6 => "Windows запретила доступ к каналу UI–агент. Используйте одну учётную запись Windows для UI и UAC.",
        7 => "Канал UI–агент был закрыт до завершения запуска.",
        8 => "Истекло время ожидания связи UI–агент.",
        _ => $"Сетевой агент завершился до подключения (код {code}). Проверьте папку agent и .NET Runtime 10 x64."
    };

    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint pid);
}
