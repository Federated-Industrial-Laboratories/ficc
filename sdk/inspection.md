# Inspection provider SDK

[Operator workflow](../docs/inspection.md) | [Dataset artifacts](artifacts.md)

The installed host exports `ficc.inspection_sdk`, independently of a source
checkout. A scanner is a separately built Python wheel with an entry point:

```toml
[project.entry-points."ficc.inspection"]
example = "example_scanner"
```

Declare a literal `API_VERSION = 1` in the package. Do not import the host's
version as the provider's declaration. The module implements:

```python
API_VERSION = 1
METADATA = {"description": "Local approved scanner", "location": "local"}

def configuration(value: dict) -> dict:
    # Validate and return bounded, JSON-compatible operator settings.
    ...

def assets(configuration: dict) -> dict[str, str]:
    # One to sixteen narrow absolute paths, outside private controller state.
    return {"engine": configuration["engine"], "rules": configuration["rules"]}

def inspect(context) -> dict:
    # Consume context.path and context.assets, never an original host path.
    ...
```

Asset keys are lowercase identifiers up to 32 characters. Assets may be ordinary
files or explicitly approved directories. The runtime maps them under `/scanner`
and supplies the mapped paths through `context.assets`. An individual asset
retains its basename. `context.configuration` is the validated settings;
`context.path` is always `/input/file`; `context.source` contains the exact file
identity, `sha256` and `size`. `context.opened()` yields a checked binary stream.
`context.verify()` hashes in bounded chunks and checks the inode before and after.
The worker invokes verification around `inspect()`. The host independently
rechecks the registered file path before publishing the receipt.

Return one JSON-compatible result of at most 65,536 bytes:

```json
{
  "outcome":"incomplete",
  "coverage":{"limits":{"expanded_bytes":419430400},"reasons":["encrypted_content"]},
  "engine":{"name":"Example","version":"1.0","sha256":"ENGINE_SHA256"},
  "signatures":{"files":[{"name":"approved.rules","sha256":"RULES_SHA256"}]},
  "findings":[]
}
```

The permitted outcomes are `no_detection`, `detected`, `incomplete`,
`unavailable` and `error`. Always state coverage bounds, archive/encryption
limitations and engine/signature provenance. Limits and unavailable decoders
must not become an unconditional clean result. Use `InspectionError(code,
message)` for safe failures; do not put credentials, raw scanner diagnostics or
unbounded filenames in public error messages. Native child output also needs a
bound. The host appends the verified input digest/size, stores each file receipt
separately and computes the aggregate result. Providers cannot grant exemptions,
clear quarantine, approve nodes or change project permissions.

The host provides the existing supervised no-network worker: exact read-only
file access, approved read-only assets, private temporary storage, cgroup limits,
current permission checks and complete child cleanup. It owns source/digest
binding and durable results. The provider owns native scanner invocation,
format-specific limits and interpretation. No daemon, public upload service or
implicit remote-file relay is part of this contract. Native engines must be
available in the approved installation; package installation does not activate
inspection. Providers are trusted deployment code, including their configuration
and asset-discovery functions in the controller. This is separate from the
ordinary workspace-module sandbox/grant model.

Build the supplied adapter independently, then install it into an environment
which already contains the built host:

```sh
python -m build --no-isolation inspection-providers/clamav
python -m pip install --no-deps inspection-providers/clamav/dist/*.whl
python -c 'from ficc.inspection_sdk import load; print(load("clamav")[1])'
```

The Apache-2.0 adapter does not bundle ClamAV or its rule databases. The native
engine and rule distribution retain their own licence and update obligations.
Qualify the actual engine, rule provenance, isolation, harmless detection,
ordinary clean file and coverage-limit behavior on the target installation.
The SDK is an extension contract, not a claim that an unshipped scanner works.
