# Process protocol 1

One action starts one process. The host writes two frames to standard input,
closes that stream and waits for the complete response. There is no persistent
session. Write diagnostics to standard error; standard output contains frames only.

A frame is a four-byte unsigned big-endian byte length followed by that many UTF-8
JSON bytes. The payload limit is 1,048,576 bytes per frame. JSON must be an object.
The host accepts exactly two response frames and at most 65,536 stderr bytes.

The host sends:

```json
{"version":1,"type":"hello","host_api":1}
{"version":1,"type":"invoke","id":"request-id","action":"echo","targets":["target-a","target-b"],"parameters":{"message":"Hello"}}
```

The module returns:

```json
{"version":1,"type":"hello","protocol":1}
{"version":1,"type":"result","id":"request-id","results":[{"target":"target-a","data":{"message":"Hello","index":0}},{"target":"target-b","data":{"message":"Hello","index":1}}]}
```

Each target requires exactly one result. A result has `target` and either `data`
or `error`. Errors have a bounded identifier `code` and a text `message` of at
most 1,024 characters. Copy the request ID and target IDs exactly. Do not return
unknown or duplicate targets. The host puts valid results in request order.

The batch contains 1 to 64 distinct target IDs, each 1 to 128 Unicode characters.
IDs are opaque. Slash, backslash, colon and NUL are forbidden in target IDs.
The action ID is declared by the manifest. Parameters are checked against its
schema before the process starts. Hand the complete batch to the implementation;
do not create a process for each target.

The SDK reads only bounded frames and refuses incomplete input, extra frames,
unsupported versions and invalid target batches. Its input is the validated host
request, not a public socket. Host JSON rejects duplicate keys, NUL, nonfinite
numbers, integers outside the exact JSON range and excessive depth. Standard
JavaScript and Rust value parsers do not detect repeated input object keys; the
host remains the authoritative validator. The C adapter uses cJSON, whose string
representation cannot preserve embedded NUL; host validation excludes it before
dispatch. Do not use these adapters as general untrusted JSON gateways.

The callback returns one full result array. The host validates every output again.
A truncated result, wrong identity, excess output or failed process is an action
failure. A per-target error is a valid batch result. Cancellation and timeout are
host responsibilities; do not detach child processes or write outside the sandbox.

Protocol 1 has no broker-call, streaming, subscription or UI-code frames. Do not
invent those messages. Native packages declare an exact Linux architecture; Python
and JavaScript packages can declare `any`. The host runs Python in isolated mode
and Node.js with native addons disabled. The Python example loads its bundled SDK
by its exact sibling path so isolated mode does not require a mutable import path.

# Process protocol 2

An executable manifest can set `runtime.protocol` to `2`. Omission selects
protocol 1. Declarative runtimes do not accept this field. Existing protocol 1
frames, SDK adapters and output rules remain unchanged. Separate broker helpers
implement protocol 2 in C, C++, Rust, Python, JavaScript and TypeScript.

Protocol 2 retains the same length prefix, JSON limits, isolated process and
complete batch result. The host sends `hello` and `invoke` with `version: 2` and
keeps standard input open. `host_api` remains `1`. The module first returns:

```json
{"version":2,"type":"hello","protocol":2}
```

The host invocation ID is exactly 32 lowercase hexadecimal characters. Before
its final result, the module may make at most 16 sequential broker calls:

```json
{"version":2,"type":"broker","id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","primitive":"system.resources.read","targets":["target-a"],"parameters":{}}
```

`id` is a unique 32-character lowercase hexadecimal broker request ID and must
not equal the parent invocation ID. `invocation_id` must match the host request.
`primitive` is a bounded identifier. The host's primitive catalog determines
which identifiers and parameter schemas are available. A module cannot select
an arbitrary command, URL, socket, credential or transport by adding fields.

Broker targets form a nonempty subset of the original frozen target list, with
no duplicates. Parameters must be an object of at most 65,536 encoded JSON bytes,
subject to the usual depth and value bounds. The host returns:

```json
{"version":2,"type":"broker-result","id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","invocation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","results":[{"target":"target-a","data":{"state":"ready"}}]}
```

Each requested broker target receives exactly one `data` or structured `error`
result. The host validates and orders this batch before writing it. A per-target
refusal can share a response with successful targets. Await the entire response
before sending another call or the final result. Pipelining, extra fields,
identity spoofing, unsupported versions and trailing frames terminate the process.
No subscription or streaming messages exist.

The final frame uses `version: 2`, `type: "result"`, the original invocation ID
in `id`, and exactly one result for every original invocation target. The host
then closes input and requires clean output closure and successful process exit.
The returned host result has `version: 2` and preserves invocation target order.

The maximum aggregate module stdout is 2,097,160 bytes across all frames. Host
input has the same aggregate bound, including the initial request and broker
responses. Stderr remains limited to 65,536 bytes. All exchanges share the
existing 10-second process deadline; a broker call does not restart it. Frame
bytes are sent only after the host verifies the kernel cgroup limits.

On cancellation, revocation, timeout or malformed traffic, the host tries one
nonblocking write of this frame before stopping the complete process cgroup:

```json
{"version":2,"type":"cancel","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

The frame is best effort and may not arrive. Process cleanup never waits for a
module acknowledgement. Disconnect is also cancellation; do not infer success
from it or replay a mutation automatically.

Executable actions require declared capabilities, current digest-specific grants
for all invocation targets, a current caller-authority check and an explicit host
broker callback. The host repeats checks before and after each callback and
periodically while awaiting it. The callback owns primitive-to-capability policy
and current per-target authorisation. Workspace and audio capabilities remain
host UI services and cannot be invoked through this process broker. Zero-capability
protocol 2 actions may complete without a callback but cannot make broker calls.

Action parameter schemas also accept `string-list` for stable row selections.
Values are unique nonempty strings. `max_items` is 1 to 128, default 64;
`max_length` applies to each item and is 1 to 8,192, default 128. Optional `choices`
restricts every item to the declared choices. Empty lists are allowed unless the
host action imposes a separate selection requirement. Scalars, duplicate items
and values outside these bounds are refused before execution.

## Broker helper interfaces

| Language | Complete-batch entry point | Broker call |
| --- | --- | --- |
| C / C++ | `ficc_serve_broker(handler)` | `ficc_broker_call(context, primitive, targets, parameters)` |
| Rust | `serve_broker(handler)` | `context.call(primitive, targets, parameters)` |
| Python | `serve_broker(handler)` | `broker(primitive, targets, parameters)` |
| JavaScript / TypeScript | `serveBroker(handler)` | `broker(primitive, targets, parameters)` |

The handler receives the full invocation request and its broker context. C and
C++ use the existing cJSON library: the call returns an owned result array or
`NULL`; free owned results with `cJSON_Delete`. Rust returns `io::Result<Vec<Value>>`.
Python and JavaScript return result lists and raise on invalid replies or
cancellation.

TypeScript declarations describe the same synchronous interface.
The context freezes invocation identity and target scope. Do not retain it after
the handler returns or make concurrent calls.

Helpers validate identities, declared frame shapes, ordered per-target outcomes,
call count, parameter size and per-direction aggregate byte limits. A cancelled
or failed broker operation prevents a successful final response, even if a handler
catches its local error. Cancellation is observed while reading a host reply;
the host still enforces termination when module code does not return to a read.
No helper obtains a network connection, provider credential or local service socket.

The resource example calls `system.resources.read` with an empty parameter object
and requires `system:read` grants for selected systems. The host checks the caller's
`nodes:read` and `resources:read` permissions and returns saved status and resource
measurements. It does not run a fresh remote command. Results can contain per-target
errors. Unknown primitives and nonempty parameters are refused by this handler.

The host remains the strict JSON trust boundary. JavaScript and Rust standard value
parsers collapse duplicate object keys; cJSON strings cannot retain embedded NUL.
Host output excludes both before transmission. These helpers consume the inherited
trusted-host channel and are not general JSON network gateways. Errors from a
broker call must not trigger automatic replay of mutations.

Provider adapters use the separate [adapter contract](ADAPTERS.md). Their broad
account grant does not replace ordinary UI module grants.
