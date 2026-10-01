# Windows endpoints

The Hyper-V provider is qualified on Windows Server 2025 evaluation in an
isolated nested lab. Actual checks cover inventory and start/history at N=1 and
N=64, plus a bootable Linux guest's start, graceful shutdown and VMConnect
display/input. Fullscreen, resize, keyboard release and grant revocation also
passed. The N=64 fixtures were diskless and CPU limited; these results do not
establish capacity for 64 guest operating systems or compatibility with other
Windows versions.
See [provider support](testing.md#runtime-modules-and-providers).

A Windows endpoint is separate from an enrolled SSH system. FICC runs on Linux.
Register a Windows HTTPS WinRM endpoint and a fixed JEA configuration. Use the
certificate PEM trust chain and the SHA-256 fingerprint of its leaf certificate.
HTTP, Basic authentication, redirects, environment proxies and arbitrary scripts
are not supported.

NTLM uses TLS channel binding. The account must have access
to the selected JEA configuration.

The Windows endpoint ID is a system target for caller scopes. Reading endpoint
metadata requires `nodes:read`. Endpoint changes require unrestricted
`nodes:write`. A provider adapter also requires its separate digest-bound
`provider:admin` grant. Ordinary workspace VM permissions do not restrict the
provider account itself. Grant provider access only to a trusted adapter.

Register one to sixteen command names with exact parameter names. Include
`Get-FICCEndpointIdentity` with no parameters. It must return one JSON string
with `machine_identity`, a stable SHA-256 identity. Each command returns one
bounded JSON string. The host sends command names and literal parameters through
PSRP `AddCommand` and `AddParameter`; it does not evaluate a command script.

The optional Windows transport has its own interpreter and current locked
libraries. It requires its recorded Linux build platform. The controller keeps
its separate platform baseline. Build and install with:

```sh
FICC_WINDOWS_BUILD_ROOT=$(mktemp -d /tmp/ficc-windows-build.XXXXXXXX)
python3 tools/windows_runtime.py build --cache "$FICC_WINDOWS_BUILD_ROOT/cache" \
  --work "$FICC_WINDOWS_BUILD_ROOT/work" --output "$FICC_WINDOWS_BUILD_ROOT/runtime"
python3 tools/windows_runtime.py install --source "$FICC_WINDOWS_BUILD_ROOT/runtime" \
  --destination /approved/new/windows-runtime
```

The build root must belong to the current account with mode 0700. Use a new
directory. The builder refuses a shared output parent or writable project
ancestors. The installation destination must be new and have an approved private
parent. Place the runtime beside the controller's Python
prefix or inside that prefix. The host checks its inventory and platform before
starting each helper. A hash inventory verifies local files; it does not identify
or authenticate the publisher. Approve the source before installation.

The build
requires a maintained Python, `zstd` and the pinned HTTPS inputs. It installs no
host packages.

The runtime includes dependency notices, Python build metadata,
CPython and Berkeley DB corresponding source, and build code.

The helper accepts at most 64 literal commands and eight concurrent requests. The
host deadline is at most 30 seconds for adapter reads and commits. JSON output is
at most 1 MiB, each HTTP response at most 2 MiB. The helper
has a 512 MiB address limit and a 20-second CPU limit. Revocation, endpoint changes,
timeout and service shutdown terminate its process group.

A lost response does
not prove that a remote change failed. The adapter keeps that operation unknown
until the operator inspects its outcome; it does not dispatch it again.

Credentials and certificate trust are private local files outside the database
and backup archive. Restore disables endpoint records and increments their
revisions. Re-enter missing accounts and trust before enabling a restored
endpoint. The host probes identity before enabling and before command dispatch.
For a command batch, the helper checks the expected machine identity in the same
authenticated JEA session before it sends the requested commands. A mismatch
refuses the complete batch. The host still checks endpoint revision and current
grants while it supervises the helper.
Connection or credential replacement and removal are refused while adapter
profiles or receipts retain the endpoint. Disable remains available.

VMConnect uses a separate display account, registered port and certificate pin.
It does not inherit the management password. A registered reference is opaque to
runtime packages and browser components. The host passes credentials only to its
private native display process. Actual provider and display support must pass
its integration checks before it is listed as qualified.
