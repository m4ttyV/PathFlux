using System.Diagnostics;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using PathFlux.Domain;
using Xunit;
namespace PathFlux.Engine.Tests;

public sealed class AgentChannelTests
{
    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void ServerRestrictsAccessToUserSidAndDeniesNetworkLogons()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var identity = WindowsIdentity.GetCurrent();
        using var server = WindowsAgentChannel.CreateServer("PathFlux-" + Guid.NewGuid().ToString("N"));
        var security = server.GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(identity.User, security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>().ToArray();
        Assert.Equal(identity.User, Assert.Single(rules, r => r.AccessControlType == AccessControlType.Allow).IdentityReference);
        Assert.Equal(new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            Assert.Single(rules, r => r.AccessControlType == AccessControlType.Deny).IdentityReference);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SeparateProcessUsesProductionChannelAndRejectsWrongParentPid(bool correctParent)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var name = "PathFlux-" + Guid.NewGuid().ToString("N");
        using var server = WindowsAgentChannel.CreateServer(name);
        var info = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "PathFlux.NetworkLab.exe"))
        { UseShellExecute = false, CreateNoWindow = true };
        info.ArgumentList.Add("pipe-probe"); info.ArgumentList.Add(name);
        info.ArgumentList.Add((correctParent ? Environment.ProcessId : Environment.ProcessId + 100000).ToString());
        using var child = Process.Start(info)!;
        try
        {
            await server.WaitForConnectionAsync(deadline.Token);
            WindowsAgentChannel.VerifyClient(server, child.Id);
            Assert.Throws<UnauthorizedAccessException>(() => WindowsAgentChannel.VerifyClient(server, child.Id + 100000));
            if (correctParent)
            {
                Assert.Equal("status", (await AgentProtocol.ReadAsync<AgentRequest>(server, deadline.Token)).Operation);
                await AgentProtocol.WriteAsync(server, new AgentReply(true, new(EngineState.Stopped, "IPC only")), deadline.Token);
            }
            await child.WaitForExitAsync(deadline.Token);
            Assert.Equal(correctParent ? 0 : 13, child.ExitCode);
        }
        finally { if (!child.HasExited) { child.Kill(true); await child.WaitForExitAsync(CancellationToken.None); } }
    }

    [Theory]
    [InlineData(2, "параметры")]
    [InlineData(3, "администратора")]
    [InlineData(4, "уже работает")]
    [InlineData(5, "процесс UI")]
    [InlineData(6, "каналу")]
    [InlineData(7, "закрыт")]
    [InlineData(8, "время")]
    [InlineData(99, "99")]
    public void EarlyAgentExitHasActionableFixedMessage(int code, string expected)
        => Assert.Contains(expected, WindowsAgentChannel.DescribeExit(code));
}
