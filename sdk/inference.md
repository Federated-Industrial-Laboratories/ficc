# Inference API and adapter contract

All management routes use `/api/v1`. Browser calls use the existing session/CSRF
contract; clients use Bearer credentials. Resources are project-scoped.

| Route | Scope | Result |
| --- | --- | --- |
| GET /models; GET /models/{id} | models:read | Immutable manifests and verified-file progress |
| POST /models | models:manage | Register a manifest; equal project manifest is idempotent |
| POST /models/{id}/acquire | models:manage | Start/resume bounded HTTPS acquisition |
| POST /models/{id}/pause | models:manage | Stop acquisition after any admitted write completes; retain its durable offset |
| POST /models/{id}/files/{index} | models:manage | `{offset,data}` with canonical base64, maximum 1 MiB decoded |
| POST /models/{id}/files/{index}/bytes?offset=N | models:manage | `application/octet-stream`, maximum 16 MiB; at most two active uploads |
| POST /models/hub-preview | models:manage | `{repository,revision,filename?,licence?}`; resolves public GGUF metadata into manifests without downloading weights |
| DELETE /models/{id}?evict=true | models:manage | Remove unreferenced metadata and optionally unshared content |
| GET /inference; GET /inference/{id} | inference:read | Specification, generation, state and workload replicas |
| POST /inference/preview | inference:manage | Validate placement and show planned reservations |
| POST /inference | inference:manage; contributor job scopes | Submit every desired replica transactionally |
| PUT /inference/{id} | inference:manage; contributor job scopes | `{revision,spec}` replaces a stopped service and starts its next generation |
| POST /inference/{id}/control/{action} | inference:manage; appropriate job scopes | `{revision,acknowledge_unknown?}`; start, drain, stop or remove |
| POST /inference/{id}/tokens | inference:manage; inference:invoke; tokens:manage | `{lifetime}` creates one service-bound invoke credential |
| GET /inference/{id}/v1/models | inference:invoke | Selected service model |
| POST /inference/{id}/v1/chat/completions | inference:invoke | Compatible JSON or SSE |
| POST /inference/{id}/v1/embeddings | inference:invoke | Capability-dependent compatible JSON |

An empty upload at the exact declared file size verifies and publishes a retained
full-length partial after interruption. Other empty writes are refused. Resumed
acquisition uses this same off-thread verification before requesting more bytes.

The service specification fields are defined by `ficc.inference.schema.Specification`:
`alias`, `model_id`, `engine`, immutable executor `runtime`, image `executable`,
`context`, `concurrency`, explicit `placements` (node ID and resource limits),
optional `gpu_layers`, `tensor_split`, `parallelism`, and request deadline.
Start/replace also requires `jobs:execute`, `contributors:read`, and `models:read`.
Stop/remove requires `jobs:cancel`. Read a fresh revision before changing state.

A runtime binds executor provider/package digest, image digest, isolation and
network. Every managed service uses `network: none`. A replica is a contributor
workload with `model_revision` and an optional immutable `endpoint` contract.
Legacy workload serialisation omits absent new fields, preserving plan digests.
Executor snapshots advertise `endpoint_version: 1`; older executors are refused
for inference placement without affecting existing job behaviour.

`ficc.inference` entry points may add engine adapters. An installed adapter factory
returns an object with `API_VERSION = 1` and
`job(specification, model_record, placement, immutable_input_references) -> Job`.
Adapters translate engine options and model semantics. Executors own processes,
resource limits and sockets; adapters must not launch unmanaged host processes.
Built-in adapters are `llama_cpp`, `ollama`, and `vllm`. An installed runtime image
is still required; selecting an adapter does not download executable code.

The executor `endpoint` action accepts bounded `open`, `read`, and `cancel`
operations, each carrying an attempt/generation/plan-digest fence and stream ID.
A read returns at most 64 KiB and a finite four-chunk queue applies backpressure.
Only admitted input IDs can feed the native model-blob upload route; arbitrary
host files, headers, addresses and management paths are unavailable. Peer loss
closes a request without replay. A controller must continue local lease renewal
independently of endpoint reads.

The internal federation integration seam is:

```python
status, chunks = await service.inference.gateway.invoke(
    service_id, "/v1/chat/completions", body, authenticated_actor
)
try:
    async for chunk in chunks:
        await transport.write(chunk)
finally:
    await chunks.aclose()
```

It rechecks current authority and service generation throughout the response.
The transport must preserve cancellation/backpressure and must authenticate its
own peer separately; peer-supplied bytes are not local FICC credentials.

A stopped managed service with an earlier unknown replica requires
`acknowledge_unknown: true` on `control/start`. Otherwise the API returns
`409 inference_unknown_outcome` before retrying any replica. Every previous
attempt must be released. The acknowledgement starts new attempts and never
replays earlier inference requests; it is rejected for other control actions.
