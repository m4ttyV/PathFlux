using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using PathFlux.Domain;
using PathFlux.Engine;

namespace PathFlux.NetworkLab;

public static class ProcessTreeAudit
{
    // The parent starts before TUN. Every request launches a fresh child; no process polling or path expansion.
    public static async Task<int> ParentAsync(string child)
    {
        while (await Console.In.ReadLineAsync() is { } line)
        {
            var args = JsonSerializer.Deserialize<string[]>(line) ?? throw new InvalidDataException();
            var result = await LabChild.RunAsync(child,args,CancellationToken.None);
            Console.WriteLine(JsonSerializer.Serialize(result));
        }
        return 0;
    }

    public static async Task<int> RunAsync(string engine,string hash,string output,CancellationToken ct,bool includeUdp = false,string? productionAgent = null)
    {
        if (!Path.IsPathFullyQualified(output) || Directory.Exists(output)) throw new InvalidOperationException("NewAbsoluteOutputRequired");
        Directory.CreateDirectory(output);
        string status="Failed",error=""; var cases=new List<object>(); NetworkSnapshot? before=null,after=null;
        bool callerElevated=LabRunner.IsElevated();
        try
        {
            if (!callerElevated && productionAgent is null) throw new InvalidOperationException("AdministratorRequired");
            if (productionAgent is not null && includeUdp) throw new InvalidOperationException("ProductionTreeUdpNotAccepted");
            if (Process.GetProcessesByName("sing-box").Length!=0) throw new InvalidOperationException("ExistingEngineMustStopFirst");
            using var binaryLock=new FileStream(engine,FileMode.Open,FileAccess.Read,FileShare.Read);
            var version=await EngineBinary.VerifyAsync(engine,hash,ct);
            await EngineBinary.VerifyProcessTreeBackendAsync(engine,ct);
            var tcpTarget=(await Dns.GetHostAddressesAsync("example.com",ct)).First(a=>a.AddressFamily==AddressFamily.InterNetwork);
            before=await NetworkSnapshot.CaptureAsync(ct);
            if (!before.CanStartLab(tcpTarget.ToString()) || !before.CanStartLab("1.1.1.1")) throw new InvalidOperationException("ExistingLabResources");
            string parentExe=LabRunner.CloneProbe(Path.Combine(output,"parent")),childExe=LabRunner.CloneProbe(Path.Combine(output,"shared-child"));
            var info=new ProcessStartInfo(parentExe){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
            info.ArgumentList.Add("tree-parent"); info.ArgumentList.Add(childExe);
            using var parent=Process.Start(info) ?? throw new InvalidOperationException("ParentLaunchFailed");
            var drain=parent.StandardError.BaseStream.CopyToAsync(Stream.Null);
            try
            {
                var discovered = (await new PathFlux.Infrastructure.ProcessDiscoveryService().GetProcessesAsync(ct)).Single(p => p.Pid == parent.Id);
                var identity=new ProcessInstanceId(parent.Id,discovered.StartTimeUtc ?? throw new InvalidOperationException("RootStartUnavailable"),discovered.SequenceNumber ?? throw new InvalidOperationException("RootSequenceUnavailable"));
                await File.WriteAllTextAsync(Path.Combine(output,"root-identity.json"),JsonSerializer.Serialize(new{identity.Pid,FileTime=identity.StartTimeUtc.UtcDateTime.ToFileTimeUtc().ToString(System.Globalization.CultureInfo.InvariantCulture),Sequence=identity.SequenceNumber?.ToString(System.Globalization.CultureInfo.InvariantCulture)}),ct);
                await using var good=new SocksConnectObserver(tcpTarget,443);
                await using var bad=new SocksConnectObserver(tcpTarget,443,true);
                foreach(string name in includeUdp ? new[]{"TcpNewChild","TcpNewGrandchild","TcpRefused","UdpNewChild","UdpNewGrandchild"} : new[]{"TcpNewChild","TcpNewGrandchild","TcpRefused"})
                {
                    bool udp=name.StartsWith("Udp",StringComparison.Ordinal),refused=name=="TcpRefused";
                    var profile=udp ? new ProxyProfile{Host="127.0.0.1",Port=1080,UdpRelayMode=UdpRelayMode.DockerNat,UdpPublishedPortFirst=20000,UdpPublishedPortLast=20030} : refused?bad.Profile:good.Profile;
                    var config=new ProxyConfiguration{Profiles=[profile],Rules=[new(){Selector=new(SelectorKind.ProcessInstance,parent.Id.ToString(),identity),IncludeChildren=true,Network=udp?NetworkTransport.Udp:NetworkTransport.Tcp,ProfileId=profile.Id}],Settings=new(){EnginePath=engine,EngineSha256=hash,ExperimentalProcessTrees=true,ExperimentalSocksUdp=udp}};
                    await using var bridges=await AgentUdpBridges.CreateAsync(config,new NoSecrets(),ct);
                    var json=JsonNode.Parse(await LabPolicy.GenerateGuardedAsync(config,ct,version,bridges.Bridges))!;
                    string target=udp?"1.1.1.1":tcpTarget.ToString();
                    json["inbounds"]![0]!["route_address"]=new JsonArray(target+"/32");
                    if(!await EngineBinary.CheckAsync(engine,json.ToJsonString(),ct)) throw new InvalidOperationException("TreeEngineCheckFailed");
                    int forwarded=good.Forwards,rejected=bad.Requests;
                    ProbeResult selected,control;
                    string diagnostic;
                    string[] probe=udp?["probe-dns","1.1.1.1","example.com"]:["probe-tls",target,"443","example.com"];
                    LabEngine? owner=null; SingBoxEngineAdapter? adapter=null;
                    try
                    {
                        if(productionAgent is null)
                        {
                            owner=await LabEngine.StartAsync(engine,json.ToJsonString(),ct);
                            await LabRunner.WaitForInterfaceAsync(owner,ct);
                            if(before.CompareDuring(await NetworkSnapshot.CaptureAsync(ct),target).Length!=0)throw new InvalidOperationException("UnsafeTreeLabScope");
                        }
                        else
                        {
                            adapter=new SingBoxEngineAdapter(new NoSecrets(),productionAgent);
                            await adapter.StartAsync(config,ct);
                        }
                        string[] childArgs=name.Contains("Grandchild",StringComparison.Ordinal)?new[]{"tree-spawn",childExe}.Concat(probe).ToArray():probe;
                        await parent.StandardInput.WriteLineAsync(JsonSerializer.Serialize(childArgs));
                        string line=await parent.StandardOutput.ReadLineAsync(ct) ?? throw new InvalidOperationException("ParentExited");
                        selected=JsonSerializer.Deserialize<ProbeResult>(line) ?? throw new InvalidDataException();
                        control=await LabChild.RunAsync(childExe,probe,ct);
                        diagnostic=owner?.Diagnostic ?? (await adapter!.GetStatusAsync(ct)).Message;
                    }
                    finally
                    {
                        if(owner is not null)await owner.DisposeAsync();
                        if(adapter is not null)
                        {
                            try { await adapter.StopAsync(CancellationToken.None); if((await adapter.GetStatusAsync(CancellationToken.None)).State!=EngineState.Stopped)throw new InvalidOperationException("AgentStopNotConfirmed"); }
                            finally { await adapter.DisposeAsync(); }
                        }
                    }
                    bool recovered=await LabRunner.WaitForRecoveryAsync(before,CancellationToken.None);
                    var stats=bridges.Snapshot();
                    bool viaProxy=udp?stats.Any(s=>s.SentPackets>0&&s.ReceivedPackets>0):good.Forwards-forwarded==1;
                    bool correct=refused?!selected.Success&&bad.Requests-rejected>0&&good.Forwards==forwarded:selected.Success&&viaProxy;
                    bool passed=correct&&control.Success&&recovered;
                    cases.Add(new{Name=name,Passed=passed,ExpectedSelectedSuccess=!refused,Selected=selected,ControlSameExecutable=control,ProxyConfirmed=viaProxy,Refusals=bad.Requests-rejected,Udp=stats,RecoveryConfirmed=recovered,EngineDiagnostic=diagnostic});
                    await Save(); if(!passed)throw new InvalidOperationException("TreeScenarioFailed_"+name);
                }
                status=includeUdp ? "PassedProcessTreeTcpUdpNewChildren_NoProductionAcceptance" : productionAgent is null ? "PassedProcessTreeTcpNewChildren_UdpNotAccepted" : "PassedProductionAgentProcessTreeTcp_UdpNotAccepted";
            }
            finally
            {
                parent.StandardInput.Close();
                if(!parent.WaitForExit(2000))parent.Kill(true);
                await parent.WaitForExitAsync(CancellationToken.None); await drain;
            }
        }
        catch(Exception ex){error=ex is InvalidOperationException?ex.Message:ex.GetType().Name;}
        finally
        {
            if(before is not null && !await LabRunner.WaitForRecoveryAsync(before,CancellationToken.None))status="RecoveryNotConfirmed";
            after=await NetworkSnapshot.CaptureAsync(CancellationToken.None); await Save();
        }
        return status.StartsWith("Passed",StringComparison.Ordinal)?0:1;
        Task Save()=>File.WriteAllTextAsync(Path.Combine(output,"report.json"),JsonSerializer.Serialize(new{Status=status,ErrorCode=error,CallerElevated=callerElevated,UdpAttempted=includeUdp,ProductionAgent=productionAgent is not null,Scope=productionAgent is null ? "Elevated isolated /32 TUN. Pinned root PID+creation+sequence, new children/grandchildren, same-executable outside control, Docker TCP. UDP only in explicit laboratory mode. No ordinary-user, orphan-race or UDP port-reuse acceptance." : "Production UAC/IPC agent and default-route TUN; caller integrity recorded separately. Exact PID+creation+sequence, Docker TCP, fail-closed. UDP trees, orphan race and UDP port reuse not accepted.",Cases=cases,Before=before,After=after},new JsonSerializerOptions{WriteIndented=true}));
    }
    private sealed class NoSecrets:PathFlux.Application.ISecretStore
    {
        public Task<ProxyCredentials?> GetAsync(string reference,CancellationToken ct)=>Task.FromResult<ProxyCredentials?>(null);
        public Task<string> StoreAsync(ProxyCredentials credentials,CancellationToken ct)=>throw new NotSupportedException();
        public Task DeleteAsync(string reference,CancellationToken ct)=>throw new NotSupportedException();
    }
}
