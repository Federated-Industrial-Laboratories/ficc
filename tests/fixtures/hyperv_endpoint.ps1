# SPDX-License-Identifier: Apache-2.0
# Execute the shipped endpoint with local CIM and Windows file-identity boundaries.
param([Parameter(Mandatory)][string]$Endpoint, [Parameter(Mandatory)][string]$InputFile)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$tree = [System.Management.Automation.Language.Parser]::ParseFile($Endpoint, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'The endpoint source has a parse error.' }
$excluded = @()
$source = foreach ($statement in $tree.EndBlock.Statements) {
    $command = $null
    if ($statement -is [System.Management.Automation.Language.PipelineAst] -and
        $statement.PipelineElements.Count -eq 1 -and
        $statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst]) {
        $command = $statement.PipelineElements[0].GetCommandName()
    }
    if ($command -in @('Import-Module', 'Add-Type', 'Export-ModuleMember')) { $excluded += $command }
    else { $statement.Extent.Text }
}
if (($excluded -join ',') -cne 'Import-Module,Add-Type,Export-ModuleMember') {
    throw 'The endpoint platform setup changed.'
}
# All function bodies, including the snapshot, selection and index functions,
# come from the product file. Only platform setup is omitted on this local host.
. ([scriptblock]::Create(($source -join "`n")))
$script:Fixture = Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
$script:Calls = [Collections.Generic.List[object]]::new()

function Get-CimInstance {
    param([string]$Namespace, [string]$ClassName, [string]$Filter)
    if ($Namespace -cne 'root/virtualization/v2') { throw 'Unexpected CIM namespace.' }
    $script:Calls.Add(@{ class_name = $ClassName; filter = $Filter })
    $rows = @($script:Fixture.cim.$ClassName)
    switch ($ClassName) {
        'Msvm_ComputerSystem' {
            if ($Filter) {
                if ($Filter -cnotmatch "^Name='([0-9a-f-]{36})'$" ) { throw 'Unexpected computer filter.' }
                $key = $Matches[1]
                $rows = @($rows | Where-Object Name -eq $key)
            }
        }
        'Msvm_VirtualSystemSettingData' {
            if ($Filter -cnotmatch "^VirtualSystemType='Microsoft:Hyper-V:System:Realized'( AND VirtualSystemIdentifier='([0-9a-f-]{36})')?$" ) {
                throw 'Unexpected configuration filter.'
            }
            $key = if ($Matches.ContainsKey(2)) { $Matches[2] } else { $null }
            $rows = @($rows | Where-Object { $_.VirtualSystemType -ceq 'Microsoft:Hyper-V:System:Realized' -and
                (-not $key -or $_.VirtualSystemIdentifier -eq $key) })
        }
        { $_ -in @('Msvm_MemorySettingData', 'Msvm_ProcessorSettingData') } {
            if ($Filter) { throw 'Unexpected metadata filter.' }
        }
        default { throw 'Unexpected CIM class.' }
    }
    return $rows
}

function Get-FICCRow($Computer, $Settings, $VM) {
    # Native Windows file identity is covered by the real provider qualification.
    # Return the metadata supplied by the unmodified product selection function.
    return @{ key = $Computer.Name.ToLowerInvariant(); configuration = $Settings.InstanceID;
        memory_bytes = $VM.MemoryStartup; vcpus = $VM.ProcessorCount }
}

$request = $script:Fixture.request | ConvertTo-Json -Compress -Depth 8
$result = Get-FICCHyperVSnapshot -Request $request | ConvertFrom-Json
@{ snapshot = $result; cim_calls = @($script:Calls); runtime = $PSVersionTable.PSVersion.ToString() } |
    ConvertTo-Json -Compress -Depth 12
