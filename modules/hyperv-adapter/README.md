# Hyper-V provider package

This package uses the controller's registered Windows transport. Provider parsing,
VM identity and fixed CIM commands are part of this installed package. The host
keeps credentials, grants, confirmation and durable operation history.

Grant `provider:admin` only to a reviewed package digest and profile. This grants
provider account authority. It is separate from a workspace module's VM read,
power and console permissions. The adapter cannot choose a host, certificate,
account or script through the transport.

The endpoint files are in `payload/endpoint`. A Windows administrator must inspect
and install them on the selected Hyper-V host. `Install-FICCHyperV.ps1` requires
the SID of a dedicated operator account. It refuses an existing installation or
session name. It does not add firewall rules, listeners, accounts or passwords.
Use the existing HTTPS listener and approved maintenance process for WinRM.

```powershell
.\Install-FICCHyperV.ps1 -OperatorSid S-1-5-21-111-222-333-1001
```

The JEA session exposes five fixed functions. Register these exact command names
in FICC. `Get-FICCEndpointIdentity` and `Get-FICCHyperVVersion` have no parameters.
`Get-FICCHyperVSnapshot`, `Invoke-FICCHyperVPower` and `Get-FICCHyperVTasks` accept
only `Request`. The transport carries literal JSON. It cannot evaluate scripts.

The endpoint runs these reviewed functions under a local virtual administrator
account. It can inspect registered configuration files and call Hyper-V. It is
not a general remote shell. Changes to the endpoint code require the same review
as a new provider package. A domain controller endpoint is not supported.

Start uses `Msvm_ComputerSystem.RequestStateChange(2)`. Guest shutdown uses
`Msvm_ShutdownComponent.InitiateShutdown` with `Force=false`. There is no stop,
reset, delete or forced shutdown fallback. The host displays the action before
commit. A positive acknowledgement can precede the final state.

VM birth uses the configuration file's volume identity, native file identity and
creation time with the VM GUID. A separate content hash records its revision.
The endpoint refuses links, unsupported files and a configuration that changes
during its bounded read. Provider checks and dispatch are separate CIM calls.
External changes can occur between them; this is not an atomic provider lock.

A known active or uncertain job retains its receipt. A lost method response stays
unknown even if the desired state appears. A positive method acknowledgement and
the same VM birth in the desired state can establish completion. Repeated reads
never dispatch the action again.

The package supports one to 64 selected VMs and at most 256 inventory rows per
request. The host grants reads and commits 30 seconds. Large
or slow providers can exceed these limits. No request silently extends them.
Inventory uses realized CIM configurations, with validated, unique VM GUIDs and
a limit of 4352 configurations. Memory and processor metadata use bounded CIM
batches. A snapshot refuses more than 8704 records of either metadata class.
Each selected VM must match one
current configuration and one memory and processor record with known units.

VMConnect selects one canonical VM GUID. The host uses the registered display
port, a separate display account and an exact certificate fingerprint. Clipboard,
audio, printer, drive and microphone redirection remain disabled.

Build both `hyperv-adapter` and the ordinary `hyperv` workspace package with the
module builder. Provider packages require the current `ficc_adapter.py` and
`ficc_module.py` SDK files. Supplied builds insert them from `sdk/python`.

This version passed actual Windows Server 2025 evaluation checks through the
installed runtime adapter: inventory and start/history at N=1 and N=64, and
a bootable Linux guest's start, graceful shutdown and VMConnect display/input.
Fullscreen, resize, keyboard release and grant revocation passed. The 64-VM
batch used diskless fixtures with CPU limits. It does not establish capacity
for 64 guest operating systems. Verify other host versions and production
workloads before deployment. See [Windows endpoints](../../docs/windows-endpoints.md).
