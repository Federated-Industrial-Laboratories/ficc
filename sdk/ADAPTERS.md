# Provider adapter protocol

A provider adapter is an installed runtime package with the `provider-adapter`
role. It cannot be a workspace panel. The owner grants `provider:admin` to its
exact digest and immutable profile. This permits control of the registered
provider account. It does not enforce read-only provider access. An ordinary UI
module still needs VM grants and host confirmation.

The host supports enrolled SSH with registered local IPC, or a controller sandbox
with a registered Windows command endpoint. A package cannot add a transport,
endpoint, credential or path. Local IPC uses an explicitly registered owned Unix
socket on the enrolled account.
New provider parsing belongs in packages. A new transport class requires a host
change and qualification.

Each exchange uses strict JSON with a four-byte big-endian byte length. Adapter
version one is separate from ordinary module protocols. Each frame is at most
1 MiB; each direction is at most 2 MiB plus eight header bytes. At most 16 sequential
transport calls are allowed. Requests contain one to 64 profiles and at most
64 resources in total.

The supplied VM workflow selects one profile per request.
A display selects one VM.

The host sends `adapter-hello` with `version:1,host_api:1`, then `adapter-invoke`
with exact fields `version:1,type,id,digest,phase,action,bindings`. IDs have 32
lowercase hexadecimal characters; digests have 64. Each binding has
`id,endpoint_id,endpoint_revision,machine_identity,consistency,resources,parameters`.
An enrolled local-IPC binding also carries `transport_binding_id`, a 32-character
lowercase hexadecimal identity. It names an existing host registration; it is
not a socket path or authority to open another endpoint. Controller Windows
bindings omit this additive field. Python and C/C++ helpers accept both shapes.

Each resource has `id,key,birth,revision,state`. The provider key is at most
128 characters. Birth identifies creation, never mutable configuration. ID is
SHA256 over sorted compact JSON `{birth,key}`, truncated to 32 hexadecimal digits.

Phases are probe/inventory/status/prepare/apply/observe/console. Action equals
phase except prepare/apply/observe use start/shutdown. Probe and inventory have
empty resource lists; other phases require resources. Apply/observe add binding
`intent:{controller,operation,digest,targets:[{id,intent}]}`. Observe also adds
`receipt:{targets:[{id,receipt}]}`, where receipt can be null after a lost response.

The adapter sends `adapter-hello` with `version:1,protocol:1`. A transport call is
`adapter-transport` with `version,id,invocation_id,profile_id,commands`. Its ID is
unique. One to 64 commands each have `command,parameters`; the full array is at
most 64 KiB. The host answers `adapter-transport-result` with the same identities
and an ordered results array.

The registered endpoint owns the command allowlist.
There is no script, URL or credential argument.

Final `adapter-result` has `version:1,id,results`. Each ordered result has
`profile_id` and exactly one of object `data` or `error:{code,message}`. Every
requested profile must occur once. Unknown fields, repeated identities and
pipelining are refused. `adapter-cancel` carries the invocation ID. The host stops
the isolated process group without waiting for provider cooperation.

VM data has these exact forms:

- Probe: `provider:{name,version,fingerprint}`.
- Inventory: `resources:[{resource,name,memory_kib,vcpus,console}],next_offset,truncated`.
  Continuation is null or an advancing offset; truncated must agree with it.
- Status: `results:[{id,data:<inventory row>}|{id,error}]` in requested order.
- Prepare: `results:[{id,intent,desired_state}|{id,error}]`. Intent is an object of
  at most 4096 bytes. Desired state is running for start, off for shutdown.
- Apply/observe: `results:[{id,receipt,observed_state?,error?}]`. Receipt has
  `state,token,completed,result`; token is an object of at most 4096 bytes. States
  are accepted/observed/failed/unknown/refused. Accepted requires an unfinished
  token; observed/failed require completion proof; refused establishes no dispatch.
- Console: `{resource,kind,binding_id,parameters}` for the exact frozen resource.
  Windows uses kind vmconnect and `parameters:{vm_id:<canonical lowercase GUID>}`.
  The host repeats the provider check at attachment and supplies private credentials.
  Enrolled Linux uses kind vnc and private
  `parameters:{pid:<positive integer>,socket_path:<absolute Unix path>,password:<8 alphanumeric characters>}`.
  Its binding ID must equal the registered transport binding. The helper requires
  an owned mode 0600 socket without path aliases, then verifies the kernel peer
  UID/PID, socket device/inode and process start identity. It repeats these checks
  at attachment and during relay. A TCP destination is not accepted by this class.

The host persists intent before dispatch and never repeats an uncertain apply.
Desired state alone does not prove the action's effect. A known unfinished task
cannot be explicitly resolved. Terminal cleanup is distinct from provider mutation.

Consistency is immutable and visible in the profile, confirmation and history.
`provider-lock` holds provider checks and dispatch under one lock.
`checked-before-dispatch` exposes an external-change race between checks and the
provider call. VirtualBox headless start and Hyper-V use the second class.

The Python helper is `python/ficc_adapter.py`; include `ficc_module.py` beside it.
Call `serve(handler)`. The handler receives `(request,transport)` and returns the
complete profile result array. `transport(profile_id,commands)` returns ordered
host command results. Any transport failure makes its context unusable, even if
the handler catches it. The helper contains no credentials.

Receipt `task_state` can be none/active/unknown/finished. If omitted, an unfinished
nonempty token is conservatively an active task. Active/unknown requires an
unfinished token; finished requires completion. A positively acknowledged method
with no provider job uses none.

Its accepted outcome can be explicitly closed
after a fresh same-birth state read, without establishing an effect. Desired state
plus the exact positive method acknowledgement can establish completion; desired
state alone cannot. Active or unknown provider tasks retain their receipt.

The C/C++ API is `ficc_serve_adapter(handler)` in `native/ficc_module.h`.
The handler receives the complete request and `ficc_adapter*` context.
`ficc_adapter_call(context,profile_id,commands)` returns an owned result array or
NULL. Compile `ficc_module.c`; its private include `ficc_adapter.inc` uses the same
bounded JSON codec. Context identities are copied before the handler runs.

A birth digest of 64 zeroes means creation identity is unavailable. Inventory
can display it with identity_ready false. Power and console refuse it. A provider
can supply an explicit operator setup command to initialize durable birth markers;
ordinary inventory and probe must not write such markers.

## Enrolled IPC and display boundary

The selected provider socket appears at `/provider/socket` inside the sandbox.
Private `/tmp`, no external network namespace, read-only package/system libraries,
no host home or devices, and the ordinary module resource limits remain in force.
An owned temporary hard link pins the selected socket inode during sandbox mount;
the helper removes that link after the invocation. The registration also pins
the peer process start identity. A daemon restart requires a new registration.

The display stream is a separate fixed helper operation. Private credentials
travel only in its bounded SSH header to the host native decoder. They do not
enter module component state, viewer references or browser tickets. A package
proposes the VM process and listener; the helper verifies the operating-system
identity and the host repeats profile, module and caller grants. An inode or
process change refuses attachment and closes an active relay.

The same bounded relay is used by the existing libvirt display helper. Provider
parsing and display setup stay in each provider package; the host has no
VirtualBox-name dispatch case. See the supplied
[VirtualBox implementation and setup](../modules/virtualbox-adapter/payload/README.md)
for a native C consumer of these contracts.
