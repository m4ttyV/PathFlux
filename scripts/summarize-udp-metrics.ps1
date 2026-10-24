param([Parameter(Mandatory = $true)][string]$Path, [string]$Output)
$ErrorActionPreference = 'Stop'
$frames = @(Get-Content -LiteralPath $Path | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
if ($frames.Count -eq 0) { throw 'No UDP metric samples.' }
$previous = @{}
$sent = 0L; $received = 0L; $reconnects = 0L; $fragments = 0L; $invalid = 0L
$states = [Collections.Generic.HashSet[string]]::new()
$errors = [Collections.Generic.HashSet[string]]::new()
$profiles = [Collections.Generic.HashSet[string]]::new()
foreach ($frame in $frames) {
    if ($frame.SchemaVersion -ne 1) { throw 'Unsupported UDP metrics schema.' }
    if ($null -eq $frame.PSObject.Properties['EngineProcessId']) { throw 'This early capture has no engine PID. Record a new capture to separate restarts reliably.' }
    if ($null -eq $frame.EngineProcessId) { $previous.Clear() }
    foreach ($udp in $frame.Udp) {
        [void]$profiles.Add([string]$udp.ProfileId); [void]$states.Add([string]$udp.State)
        if ($udp.LastError) { [void]$errors.Add([string]$udp.LastError) }
        # Stopped snapshots retain history for the UI; never count that history as a new session.
        if ($null -eq $frame.EngineProcessId) { continue }
        $key = "$($frame.EngineProcessId):$($udp.ProfileId)"
        $old = $previous[$key]
        if ($old -and ([long]$udp.SentPackets -lt [long]$old.SentPackets -or [long]$udp.ReceivedPackets -lt [long]$old.ReceivedPackets)) { $old = $null }
        $sent += [Math]::Max(0L, [long]$udp.SentPackets - $(if ($old) { [long]$old.SentPackets } else { 0L }))
        $received += [Math]::Max(0L, [long]$udp.ReceivedPackets - $(if ($old) { [long]$old.ReceivedPackets } else { 0L }))
        $reconnects += [Math]::Max(0L, [long]$udp.Reconnects - $(if ($old) { [long]$old.Reconnects } else { 0L }))
        $fragments += [Math]::Max(0L, [long]$udp.DroppedFragments - $(if ($old) { [long]$old.DroppedFragments } else { 0L }))
        $invalid += [Math]::Max(0L, [long]$udp.DroppedInvalid - $(if ($old) { [long]$old.DroppedInvalid } else { 0L }))
        $previous[$key] = $udp
    }
}
$summary = [ordered]@{
    Scope = 'Observed transport counters; not Discord acceptance or end-to-end loss measurement'
    Samples = $frames.Count; FirstUtc = $frames[0].TimestampUtc; LastUtc = $frames[-1].TimestampUtc
    Profiles = @($profiles); ObservedSentPackets = $sent; ObservedReceivedPackets = $received
    Reconnects = $reconnects; DroppedFragments = $fragments; DroppedInvalid = $invalid
    States = @($states); ConnectionErrors = @($errors)
    Rtt = 'Not measured'; Jitter = 'Not measured'; PacketLoss = 'Not measured: sent/received counts are asymmetric'
}
$json = $summary | ConvertTo-Json -Depth 6
if ($Output) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($Output), $json) }
$json
