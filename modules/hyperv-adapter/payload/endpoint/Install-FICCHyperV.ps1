# SPDX-License-Identifier: Apache-2.0
# Install the reviewed fixed endpoint as an administrator on the selected host.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-[0-9-]+$')][string]$OperatorSid,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9.-]{0,63}$')][string]$ConfigurationName = 'FICC.HyperV'
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator access is required.' }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { throw 'Domain controller endpoints are not supported.' }
$sid = New-Object Security.Principal.SecurityIdentifier($OperatorSid)
$account = $sid.Translate([Security.Principal.NTAccount]).Value
$base = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules\FICCHyperV'
if (Test-Path -LiteralPath $base) { throw 'The endpoint directory exists. Inspect it before replacing this version.' }
if (Get-PSSessionConfiguration -Name $ConfigurationName -ErrorAction SilentlyContinue) { throw 'The endpoint name exists.' }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @('S-1-5-18','S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($identity)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
New-Item -ItemType Directory -Path $base | Out-Null
Set-Acl -LiteralPath $base -AclObject $acl
$capabilities = Join-Path $base 'RoleCapabilities'
New-Item -ItemType Directory -Path $capabilities | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'FICCHyperV.psm1') -Destination $base
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'FileIdentity.cs') -Destination $base
Add-Type -Path (Join-Path $base 'FileIdentity.cs') -OutputAssembly (Join-Path $base 'FileIdentity.dll') -OutputType Library
New-ModuleManifest -Path (Join-Path $base 'FICCHyperV.psd1') -RootModule 'FICCHyperV.psm1' -ModuleVersion '1.0.0' `
    -Guid '5d39b620-a306-47ee-b7c8-4bcb599a90ca' -Author 'Federated Industrial Laboratories' `
    -FunctionsToExport @('Get-FICCEndpointIdentity','Get-FICCHyperVVersion','Get-FICCHyperVSnapshot','Invoke-FICCHyperVPower','Get-FICCHyperVTasks')
New-PSRoleCapabilityFile -Path (Join-Path $capabilities 'FICCHyperV.psrc') -ModulesToImport 'FICCHyperV' `
    -VisibleFunctions @('Get-FICCEndpointIdentity','Get-FICCHyperVVersion','Get-FICCHyperVSnapshot','Invoke-FICCHyperVPower','Get-FICCHyperVTasks')
$roles = @{}
$roles[$account] = @{RoleCapabilities='FICCHyperV'}
$config = Join-Path $base 'FICC.HyperV.pssc'
New-PSSessionConfigurationFile -Path $config -SessionType RestrictedRemoteServer -LanguageMode NoLanguage `
    -RunAsVirtualAccount -RoleDefinitions $roles
Test-PSSessionConfigurationFile -Path $config | Out-Null
Register-PSSessionConfiguration -Name $ConfigurationName -Path $config -NoServiceRestart -Force
Write-Output 'The fixed endpoint is registered. Restart WinRM during an approved maintenance period.'
