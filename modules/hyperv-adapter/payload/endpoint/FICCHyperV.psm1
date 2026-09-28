# SPDX-License-Identifier: Apache-2.0
# Fixed Hyper-V commands. All provider interpretation ships with the adapter.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Namespace = 'root/virtualization/v2'
Add-Type -Path (Join-Path $PSScriptRoot 'FileIdentity.dll')

function Get-FICCHash([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Read-FICCRequest([string]$Request) {
    if ($Request.Length -gt 60000) { throw 'Request size refused.' }
    return ConvertFrom-Json -InputObject $Request -ErrorAction Stop
}
function Assert-FICCFields($Value, [string[]]$Names) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    if (($actual -join ',') -cne (($Names | Sort-Object) -join ',')) { throw 'Request fields refused.' }
}
function Assert-FICCGuid([string]$Value) {
    if ($Value -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'VM identity refused.' }
}
function Assert-FICCIds($Ids, [int]$Maximum = 64) {
    if ($Ids -isnot [Array] -or $Ids.Count -gt $Maximum) { throw 'VM batch refused.' }
    foreach ($id in $Ids) { Assert-FICCGuid $id }
    if (@($Ids | Select-Object -Unique).Count -ne $Ids.Count) { throw 'Repeated VM identity.' }
}
function Get-FICCEndpointIdentity {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { throw 'Domain controller endpoints are not supported.' }
    $machine = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID.ToLowerInvariant()
    @{ machine_identity = Get-FICCHash ($machine.ToLowerInvariant() + ':' + $uuid) } | ConvertTo-Json -Compress
}
function Get-FICCHyperVVersion {
    $version = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
    Get-VMHost -ErrorAction Stop | Out-Null
    @{ version = [string]$version; backend = 1 } | ConvertTo-Json -Compress
}
function Get-FICCRow($Computer, $Settings, $VM) {
    $key = $Computer.Name.ToLowerInvariant()
    Assert-FICCGuid $key
    $root = [IO.Path]::GetFullPath($Settings.ConfigurationDataRoot)
    if ([IO.Path]::IsPathRooted($Settings.ConfigurationFile)) { throw 'Configuration path refused.' }
    $path = [IO.Path]::GetFullPath((Join-Path $root $Settings.ConfigurationFile))
    if (-not $path.StartsWith($root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Configuration path refused.' }
    $identity = [FICCFileIdentity]::Read($path)
    return @{ key = $key; birth = Get-FICCHash ($key + ':' + $identity[0]); revision = $identity[1];
        name = [string]$Computer.ElementName; state = [int]$Computer.EnabledState;
        memory_bytes = [long]$VM.MemoryStartup; vcpus = [int]$VM.ProcessorCount; console = $true }
}
function Get-FICCSelected([string[]]$Ids) {
    if ($Ids.Count -eq 0) { return }
    $filter = ($Ids | ForEach-Object { "Name='$_'" }) -join ' OR '
    $computers = @(Get-CimInstance -Namespace $script:Namespace -ClassName Msvm_ComputerSystem -Filter $filter)
    $filter = ($Ids | ForEach-Object { "VirtualSystemIdentifier='$_'" }) -join ' OR '
    $settings = @(Get-CimInstance -Namespace $script:Namespace -ClassName Msvm_VirtualSystemSettingData -Filter ("VirtualSystemType='Microsoft:Hyper-V:System:Realized' AND (" + $filter + ')'))
    $vms = @(Get-VM -Id $Ids -ErrorAction SilentlyContinue)
    $output = @()
    foreach ($key in $Ids) {
        $computer = @($computers | Where-Object Name -eq $key)
        $setting = @($settings | Where-Object VirtualSystemIdentifier -eq $key)
        $vm = @($vms | Where-Object { $_.Id.ToString() -eq $key })
        if ($computer.Count -eq 1 -and $setting.Count -eq 1 -and $vm.Count -eq 1) {
            $output += Get-FICCRow $computer[0] $setting[0] $vm[0]
        }
    }
    return $output
}
function Get-FICCHyperVSnapshot {
    param([Parameter(Mandatory)][string]$Request)
    $value = Read-FICCRequest $Request
    Assert-FICCFields $value @('ids','offset','limit')
    Assert-FICCIds $value.ids
    if (($value.offset -isnot [int] -and $value.offset -isnot [long]) -or $value.offset -lt 0 -or $value.offset -gt 4096 -or
        ($value.limit -isnot [int] -and $value.limit -isnot [long]) -or $value.limit -lt 1 -or $value.limit -gt 256) { throw 'Inventory range refused.' }
    $next = $null
    $ids = @($value.ids)
    if ($ids.Count -eq 0) {
        $all = @(Get-VM | Sort-Object Id | Select-Object -First 4353)
        if ($all.Count -gt 4352) { throw 'Provider inventory exceeds its bound.' }
        $ids = @($all | Select-Object -Skip $value.offset -First $value.limit | ForEach-Object { $_.Id.ToString().ToLowerInvariant() })
        if (($value.offset + $value.limit) -lt $all.Count) {
            $next = $value.offset + $value.limit
            if ($next -gt 4096) { throw 'Provider continuation exceeds its bound.' }
        }
    }
    @{ rows = @(Get-FICCSelected $ids); next_offset = $next } | ConvertTo-Json -Compress -Depth 8
}
function Invoke-FICCHyperVPower {
    param([Parameter(Mandatory)][string]$Request)
    $value = Read-FICCRequest $Request
    Assert-FICCFields $value @('targets')
    if ($value.targets -isnot [Array] -or $value.targets.Count -lt 1 -or $value.targets.Count -gt 64) { throw 'Action batch refused.' }
    $ids = @()
    foreach ($target in $value.targets) {
        Assert-FICCFields $target @('resource','action','method')
        Assert-FICCFields $target.resource @('id','key','birth','revision','state')
        Assert-FICCGuid $target.resource.key
        if ($target.resource.birth -cnotmatch '^[0-9a-f]{64}$' -or $target.resource.revision -cnotmatch '^[0-9a-f]{64}$' -or
            $target.action -notin @('start','shutdown') -or
            $target.method -cne @{start='RequestStateChange';shutdown='InitiateShutdown'}[$target.action]) { throw 'Action fields refused.' }
        $ids += $target.resource.key
    }
    Assert-FICCIds $ids
    $rows = @(Get-FICCSelected $ids)
    $results = @()
    foreach ($target in $value.targets) {
        $resource = $target.resource
        $result = @{ key=$resource.key; birth=$resource.birth; dispatched=$false; return_value=0; job=$null }
        $row = @($rows | Where-Object key -eq $resource.key)
        $expected = @{start=3;shutdown=2}[$target.action]
        if ($row.Count -ne 1 -or $row[0].birth -cne $resource.birth -or $row[0].revision -cne $resource.revision -or $row[0].state -ne $expected) {
            $results += $result; continue
        }
        # Recheck this VM immediately before dispatch. The CIM calls are not atomic.
        $fresh = @(Get-FICCSelected @($resource.key))
        if ($fresh.Count -ne 1 -or $fresh[0].birth -cne $resource.birth -or $fresh[0].revision -cne $resource.revision -or $fresh[0].state -ne $expected) {
            $results += $result; continue
        }
        $computer = Get-CimInstance -Namespace $script:Namespace -ClassName Msvm_ComputerSystem -Filter ("Name='" + $resource.key + "'")
        if ($target.action -eq 'start') {
            $reply = Invoke-CimMethod -InputObject $computer -MethodName RequestStateChange -Arguments @{RequestedState=[UInt16]2}
            if ($reply.Job) { $result.job = $reply.Job.InstanceID.ToLowerInvariant() }
        } else {
            $shutdown = @(Get-CimAssociatedInstance -InputObject $computer -ResultClassName Msvm_ShutdownComponent)
            if ($shutdown.Count -ne 1) { $results += $result; continue }
            $reply = Invoke-CimMethod -InputObject $shutdown[0] -MethodName InitiateShutdown -Arguments @{Force=$false;Reason='FICC confirmed guest shutdown'}
        }
        $result.dispatched = $true
        $result.return_value = [long]$reply.ReturnValue
        $results += $result
    }
    @{ results=$results } | ConvertTo-Json -Compress -Depth 8
}
function Get-FICCHyperVTasks {
    param([Parameter(Mandatory)][string]$Request)
    $value = Read-FICCRequest $Request
    Assert-FICCFields $value @('ids')
    Assert-FICCIds $value.ids
    $all = @(Get-CimInstance -Namespace $script:Namespace -ClassName Msvm_ConcreteJob)
    $results = @()
    foreach ($id in $value.ids) {
        $job = @($all | Where-Object InstanceID -eq $id)
        $results += @{id=$id;state=$(if ($job.Count -eq 1) {[int]$job[0].JobState} else {0});
            error=$(if ($job.Count -eq 1) {[long]$job[0].ErrorCode} else {0})}
    }
    @{ results=$results } | ConvertTo-Json -Compress -Depth 8
}
Export-ModuleMember -Function Get-FICCEndpointIdentity,Get-FICCHyperVVersion,Get-FICCHyperVSnapshot,Invoke-FICCHyperVPower,Get-FICCHyperVTasks
