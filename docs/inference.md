# Managed inference and models

FICC runs persistent inference services through the contributor executor. Each
replica is a durable workload with an immutable image, model revision, resource
reservation and short renewable local execution lease. Select several cards in
one placement to span a model across cards; select several contributors to run
independent replicas behind the same service endpoint.

## Start a service

1. Configure a workload scheduler and connect managed contributors using the
   [executor installation contract](../packaging/remote/executor/README.md).
   Install the approved inference image as an immutable OCI archive. The executor
   advertises its exact provider package and image digests.
2. Open **Models** and choose **Import from Hugging Face** for public single-file
   GGUF weights. Enter the repository, inspect its quantizations and sizes, then
   register the selected revision. For split or safetensors weights, use **Register
   model** with an explicit manifest. Acquire approved HTTPS sources or upload the
   named local files. Uploads resume after interruption.
   FICC checks every complete SHA256 before making the revision available.
3. Open **Inference**, choose **New service**, and select the revision, engine,
   approved runtime and contributors. Choose the GPU UUIDs separately on each
   contributor. The executable field is the path inside the approved image.
4. Set context and request concurrency, preview the reservation, then start.
   The view reports preparation, loading, readiness and retained failures.
5. Select the ready service and send a test prompt. Cancel closes that request's
   engine stream. The service remains resident until drained or stopped.

The llama.cpp adapter uses native Unix sockets and layer splitting. Its context
setting is per request slot: the server receives context multiplied by concurrency.
The Ollama adapter owns a dedicated daemon and store, disables cloud features,
imports verified blobs through the native API and checks the resident model. It
keeps the GPU lease while the daemon exists. Ollama decides its actual distribution
across the selected visible cards; FICC does not promise exact per-card placement.
The vLLM adapter is available when an approved vLLM image is installed. It accepts
complete safetensors snapshots, uses explicit context/concurrency and tensor or
pipeline parallelism, and has private shared memory charged to the memory ceiling.
Its library search includes the standard NVIDIA, CUDA and system library
directories, so Triton can discover approved driver mounts without changing the
read-only image's linker cache. Driver files still require the executor's explicit
CDI mappings and verified digests.

An engine image must support the selected adapter's flags and API. Successful
startup alone does not mark a replica ready: FICC checks the endpoint and selected
model identity. Runtime compatibility is based on that contract, rather than a
fixed upstream version equality check. An image update creates a new specification;
restarts retain the original digest.

## Model manifest

The Hub import resolves a branch or tag to a full source commit and retains the
publisher's declared SHA256, size and licence. It uses the public Hub metadata API;
registration does not download weights. Gated and private models can be imported
with an explicit manifest and locally acquired files. Review the publisher's
licence before acquisition.

```sh
ficc model-hub-import --repository Qwen/Qwen3-0.6B-GGUF \
  --filename Qwen3-0.6B-Q8_0.gguf --revision main
```

A model revision contains source provenance, licence, format, quantisation, an
entrypoint and every required file, including split weights and tokenizer/config
files. Keep files in a flat snapshot and retain their original names.

```json
{
  "name": "Project assistant",
  "revision": "immutable-source-commit",
  "source": "publisher/model",
  "licence": "Apache-2.0",
  "format": "gguf",
  "quantization": "Q4_K_M",
  "entrypoint": "model.gguf",
  "capabilities": ["chat"],
  "files": [{
    "name": "model.gguf",
    "digest": "sha256:REPLACE_WITH_64_HEXADECIMAL_DIGEST",
    "bytes": 123456789,
    "url": "https://huggingface.co/publisher/model/resolve/COMMIT/model.gguf"
  }]
}
```

The URL is optional for local upload. Use the publisher's exact size and digest.
Browser and CLI uploads use bounded 16 MiB binary chunks. Each acknowledged offset
is durable; the last chunk also verifies the complete SHA256 before atomic
publication. Model lists remain responsive while a large HDD object is verified.
If the controller stops after the final write, another upload or acquisition
verifies and publishes those retained bytes without downloading them again.
HTTPS acquisition follows only explicitly allowed hosts, including redirects.
The defaults cover Hugging Face and its documented download hosts. Source URLs
must not contain embedded credentials. Interrupted acquisitions retain the durable
partial offset and verify the full digest before atomic publication. A digest
mismatch discards the partial object. Different revisions never silently update a
running service.

Hugging Face publishes its current storage hostnames in its
[download documentation](https://huggingface.co/docs/hub/models-downloading) and
`https://huggingface.co/.well-known/meta.json`. The default list includes its US
AWS/GCP CDN and US/EU Xet endpoints. Explicit administrator host lists replace
these defaults and must include the redirects required by the chosen source.

Cache objects are project-scoped. Identical content does not confer access across
projects. Remove referencing services and workloads before removing a revision.
The remove action can evict unreferenced files; shared files within the same
project remain while another revision references them.

## Storage

The default controller library is `models/` below the private state directory.
To select an existing dedicated volume, stop the controller and run:

```sh
ficc model-store-configure --state-dir STATE --directory /srv/ficc-models
```

This provisions only the selected private directory and records its filesystem and
inode binding. If the configured volume disappears or changes, startup refuses
it. It does not fall back to the root filesystem. Use a stable system mount for
production and arrange service mount dependencies. Add repeated `--https-host`
options to replace the exact download-host allowlist.

Keep the controller database and executor ledger on storage with reliable low
latency. A large HDD model library is suitable for weights; colocating metadata
with heavy image extraction can delay durable lease writes and trigger the
executor watchdog. Its fail-stop bound remains enabled.

The executor optionally accepts `model_cache` in its administrator configuration:

```json
{
  "directory": "/srv/ficc-node-models",
  "filesystem_uuid": "REPLACE_WITH_FILESYSTEM_UUID",
  "maximum_bytes": 53687091200,
  "maximum_files": 256
}
```

Create the private root-owned directory on the intended filesystem first. The
cache validates its UUID, bounds retained data, and verifies copies when staging
an attempt. Active attempt references prevent cache eviction. The attempt still
owns its independent finite storage allocation; caches cannot bypass that bound.
A cache fill failure leaves the verified attempt input intact. Reusing a complete
node cache avoids downloading the weights again.

To pre-stage weights already present on a node, stop its supervisor and release
all retained attempts, then use the normal administrator interface:

```sh
python -m ficc.execution model-cache-import --config /etc/ficc/executor.json \
  --project PROJECT_ID --source /srv/downloads/model.gguf \
  --digest sha256:EXPECTED_SHA256 --bytes EXPECTED_BYTE_COUNT
python -m ficc.execution model-cache-list --config /etc/ficc/executor.json
python -m ficc.execution model-cache-evict --config /etc/ficc/executor.json \
  --project PROJECT_ID --digest sha256:EXPECTED_SHA256
```

Import verifies every byte and atomically publishes the project-bound object.
These commands require root and validate the configured volume UUID. They never
fall back to another filesystem. An exclusive cache lock prevents concurrent
administration from removing an active import or racing supervisor startup.
A normal cold placement can transfer weights
through the contributor channel; compatible executors advertise 8 MiB durable
chunks. The supervisor admits at most 16 MiB of aggregate incoming frames before
reading their bodies, keeping concurrent staging within its memory limit.

Reserve space for the immutable source, staged attempt input, image archive and
extraction, runtime temporary files and writable engine store. Ollama additionally
needs space for its blob import. Size the inode reservation from the image's
extracted files as well as the weights: Python-based engines can contain hundreds
of thousands of files. A model's byte size alone does not describe that requirement.
The executor's finite filesystem is the final
bound. The service preview reports reservation sizes rather than a promise that
all engine-specific allocations will fit.

An approved image archive that is already immutable, root-owned and publicly
readable below root-owned searchable directories can be loaded directly by the
trusted runtime loader. Its descriptor is checked against the recorded identity
and closed before payload creation; the archive is never mounted into the payload.
Private archives retain their per-attempt copy. Budget for the image loader's
temporary compressed layers and extracted layers in either case.

## Lifecycle and access

**Drain** refuses new invocations and waits for current requests before stopping.
**Stop** cancels execution immediately. A GPU reservation is retained until local
cleanup is observed; uncertain outcomes do not become success. **Start** creates
another attempt only after prior storage is released. **Configure** changes a
stopped service's model or replica placements and starts its next generation.
Preview and plan the interruption before changing placements. Replica count is
independent of the number of cards assigned to each replica.

The FICC gateway serves this compatibility subset under the endpoint displayed
for each service:

- `GET /v1/models`
- `POST /v1/chat/completions`, including SSE streaming
- `POST /v1/embeddings`, when declared by the model and supported by its engine

Use an `inference:invoke` credential. **Create client token** issues a one-hour
invoke-only credential bound to that service. It is shown once and can be revoked
through Access. The token cannot read model files or control processes. Normal
project credentials may deliberately cover all services in their project.
Current project authority is checked while streaming. Requests have finite
concurrency, body/output buffers and deadlines. An interrupted request is not
replayed after generation starts.

Managed engines have no host network. llama.cpp binds a private Unix socket;
TCP-only engines use a fixed loopback connector inside the same isolated network
namespace. The executor verifies socket ownership, peer credentials, cgroup and
attempt generation and forwards only declared inference routes. Native engine
administration is not exposed through the public gateway.

## CLI and recovery

```sh
ficc model-create --input model.json
ficc model-upload MODEL_ID --directory /path/to/snapshot
ficc model-acquire MODEL_ID
ficc model-pause MODEL_ID
ficc model-get MODEL_ID
ficc inference-preview --input service.json
ficc inference-create --input service.json
ficc inference-list
ficc inference-chat SERVICE_ID --prompt 'Explain this system.'
ficc inference-token SERVICE_ID
ficc inference-drain SERVICE_ID --revision CURRENT_REVISION
ficc inference-stop SERVICE_ID --revision CURRENT_REVISION
ficc inference-start SERVICE_ID --revision CURRENT_REVISION
```

The API specification is available at [sdk/inference.md](../sdk/inference.md).
Use `--state-dir` and `--project` for another local installation/project.
`model-acquire` waits for acquisition to finish. Interrupting the command pauses
the download; another acquisition resumes its durable offset.

After supervisor loss, an earlier replica may have an unknown outcome. Stop the
service and wait for confirmed release. Start then requires explicit acknowledgement:
use the console's "Acknowledge and start new attempts" action, or add
`--acknowledge-unknown` to `inference-start`. This starts new attempts without
replaying previous inference requests. Acknowledgement does not bypass cleanup,
resource release or normal authorization.

Backup includes immutable manifests and service metadata, excludes weights and
source credentials, and requires the same quiescent released-workload boundary
as other contributor jobs. Restore suspends services and clears external model
volume bindings. Reconfigure storage, reacquire or import the verified files and
reconcile contributors before explicit restart. Keep the previous installation
and its state backup until the new candidate is qualified.

## Attach an existing compatible service

An attached service uses the same FICC endpoint, project authorization, client
credentials, health state and request cancellation. FICC does not start or stop
its external server. Stop and drain disable routing through FICC only.

With the controller stopped, an administrator can approve profiles:

```json
[
  {
    "name": "existing-server",
    "projects": ["PROJECT_ID"],
    "url": "https://inference.example/v1",
    "model": "existing-model-id",
    "capabilities": ["chat"],
    "concurrency": 2,
    "deadline_seconds": 120,
    "token_file": "/private/endpoint-token"
  }
]
```

```sh
ficc inference-endpoints-configure --state-dir /private/ficc --input profiles.json
```

Restart the controller, open Inference and choose **Attach endpoint**. Only
profiles approved for the current project appear. HTTPS uses normal certificate
verification. Plain HTTP requires an explicit numeric loopback address. Redirects
and environment proxy settings are disabled. The optional token file must be a
private regular file owned by the controller account. Its contents are never
returned by the API. Model health requires the configured model in `/v1/models`.

For CLI or API creation, read `endpoint_profiles` from `GET /api/v1/inference`,
then submit the selected immutable profile digest:

```json
{"alias":"existing-assistant","engine":"attached","profile":"existing-server","profile_digest":"sha256:PROFILE_DIGEST"}
```

A profile change requires reconfiguration of its stopped services. Restored state
has no active endpoint profiles; the administrator must explicitly bind them
again. An attached service does not acquire weights or reserve contributor GPUs.

Use `ficc model-pause MODEL_ID` or **Pause acquisition** to stop an HTTPS download.
A later acquire resumes at its durable offset. Use `ficc inference-replace ID
--revision REVISION --input service.json` to configure a stopped service with a
new model, placement or approved endpoint profile.
