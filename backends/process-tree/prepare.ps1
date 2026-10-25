param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
$sourceRoot=(Resolve-Path -LiteralPath $Source).Path
if(-not(Test-Path -LiteralPath (Join-Path $sourceRoot 'go.mod'))){throw 'SingBoxSourceRequired'}
$marker=Join-Path $sourceRoot '.pathflux-tree-overlay'
if(Test-Path -LiteralPath $marker){throw 'UseFreshPinnedSource_OverlayAlreadyApplied'}
function Edit-Source([string]$Relative,[string]$Before,[string]$After){
    $path=Join-Path $sourceRoot $Relative
    $text=[IO.File]::ReadAllText($path).Replace("`r`n","`n")
    if(-not $text.Contains($Before)){throw "UnexpectedPinnedSource: $Relative"}
    [IO.File]::WriteAllText($path,$text.Replace($Before,$After),[Text.UTF8Encoding]::new($false))
}
Edit-Source 'adapter/platform.go' "type ConnectionOwner struct {" "type ConnectionOwner struct {`n`tPathFluxStarted uint64`n`tPathFluxSequence uint64"
Edit-Source 'adapter/inbound.go' '"time"' "`"time`"`n`t`"sync`""
Edit-Source 'adapter/inbound.go' 'type InboundContext struct {' "type InboundContext struct {`n`tPathFluxTreeResults *sync.Map"
Edit-Source 'option/rule.go' "type RawDefaultRule struct {" @'
type PathFluxTreeOptions struct {
    PID uint32 `json:"pid,omitempty"`
    Started uint64 `json:"started,omitempty,string"`
    Sequence uint64 `json:"sequence,omitempty,string"`
    Name string `json:"name,omitempty"`
    Path string `json:"path,omitempty"`
    Unresolved bool `json:"unresolved,omitempty"`
    SelfOnly bool `json:"self_only,omitempty"`
}
type RawDefaultRule struct {
    PathFluxTree *PathFluxTreeOptions `json:"pathflux_process_tree,omitempty"`
'@
Edit-Source 'route/rule/rule_default.go' "`trouter := service.FromContext[adapter.Router](ctx)" @'
    if options.PathFluxTree != nil {
        item,err := NewPathFluxTreeItem(*options.PathFluxTree)
        if err != nil { return nil,err }
        rule.items = append(rule.items,item)
        rule.allItems = append(rule.allItems,item)
    }
    router := service.FromContext[adapter.Router](ctx)
'@
# This boolean affects only configurations using the experimental rule extension.
Edit-Source 'route/router.go' "type Router struct {" "type Router struct {`n`tpathFluxTrees bool`n`tpathFluxUdpTrees bool"
Edit-Source 'route/router.go' "needFindProcess:   hasRule(options.Rules, isProcessRule)" "pathFluxUdpTrees: hasRule(options.Rules, func(r option.DefaultRule) bool { if r.PathFluxTree == nil { return false }; if len(r.Network) == 0 { return true }; for _,n := range r.Network { if n == `"udp`" { return true } }; return false }),`n`t`tpathFluxTrees: hasRule(options.Rules, func(r option.DefaultRule) bool { return r.PathFluxTree != nil }),`n`t`tneedFindProcess:   hasRule(options.Rules, isProcessRule)"
Edit-Source 'route/process_cache.go' "`tkey := processCacheKey{" "`tif r.pathFluxTrees { return process.FindProcessInfo(r.processSearcher,ctx,network,source,destination) }`n`tkey := processCacheKey{"
Edit-Source 'common/process/searcher_windows.go' '"syscall"' @'
"syscall"
    T "github.com/sagernet/sing-box/common/pathfluxtree"
'@
Edit-Source 'common/process/searcher_windows.go' 'winiphlpapi.FindPid(network, source)' 'pathFluxFindOwner(network, source, destination)'
Edit-Source 'common/process/searcher_windows.go' 'return &adapter.ConnectionOwner{ProcessID: pid, ProcessPath: path, UserId: -1}, nil' @'
    record,identityErr := (T.NativeSource{}).Read(pid)
    if identityErr != nil || record.Path != path { return nil,T.ErrUnavailable }
    again,lookupErr := pathFluxFindOwner(network,source,destination)
    if lookupErr != nil || again != pid { return nil,T.ErrUnavailable }
    verified,verifyErr := (T.NativeSource{}).Read(pid)
    if verifyErr != nil || verified.Identity != record.Identity { return nil,T.ErrUnavailable }
    return &adapter.ConnectionOwner{ProcessID: pid, ProcessPath: path, UserId: -1, PathFluxStarted:record.Started,PathFluxSequence:record.Sequence}, nil
'@
Edit-Source 'route/route.go' "`tmetadata.Network = N.NetworkUDP" @'
    metadata.Network = N.NetworkUDP
    if r.pathFluxUdpTrees && metadata.InboundType == C.TypeTun {
        r.searchProcessInfo(ctx,&metadata)
        if metadata.ProcessInfo == nil || metadata.ProcessInfo.PathFluxStarted == 0 { return E.New("PathFluxUdpOwnerUnavailable") }
        conn = &pathFluxPacketOwner{PacketConn:conn,router:r,ctx:ctx,source:metadata.Source.AddrPort(),destination:metadata.Destination.AddrPort(),owner:T.Identity{PID:metadata.ProcessInfo.ProcessID,Started:metadata.ProcessInfo.PathFluxStarted,Sequence:metadata.ProcessInfo.PathFluxSequence}}
    }
'@
Edit-Source 'route/route.go' '"github.com/sagernet/sing-box/adapter"' @'
"github.com/sagernet/sing-box/adapter"
    T "github.com/sagernet/sing-box/common/pathfluxtree"
'@
$target=Join-Path $sourceRoot 'common/pathfluxtree'
New-Item -ItemType Directory -Path $target -Force | Out-Null
foreach($name in @('tree.go','native_windows.go','tree_test.go')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $target $name)}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'overlay/rule_item_pathflux_tree.go') -Destination (Join-Path $sourceRoot 'route/rule/rule_item_pathflux_tree.go')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'overlay/pathflux_packet_owner.go') -Destination (Join-Path $sourceRoot 'route/pathflux_packet_owner.go')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'overlay/cmd_pathflux_capabilities.go') -Destination (Join-Path $sourceRoot 'cmd/sing-box/cmd_pathflux_capabilities.go')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'overlay/pathflux_owner_windows.go') -Destination (Join-Path $sourceRoot 'common/process/pathflux_owner_windows.go')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'overlay/rule_item_pathflux_tree_test.go') -Destination (Join-Path $sourceRoot 'route/rule/rule_item_pathflux_tree_test.go')
[IO.File]::WriteAllText($marker,'Experimental PathFlux tree overlay v1. Upstream v1.14.3; not an official sing-box binary.')
