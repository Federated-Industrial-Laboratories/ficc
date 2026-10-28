# Cluster federation

[Documentation](README.md) | [Inference](inference.md) | [Federation API](../sdk/federation.md)

Federation shares selected inference services, model revisions and deployment
operations between independently managed FICC clusters. Every inter-cluster
request travels through HyperNet application streams. Each cluster retains its
own project policy, model store, resource admission and executor credentials.
The initial topology requires both clusters in the same HyperNet network and
incarnation. There is no direct HTTP, SSH or alternate relay fallback.

## Prepare HyperNet

Use Core and Suite with application-stream protocol 7 support. The first
compatible feature release is HyperNet 0.9.0. Follow the
[Suite application-stream guide](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/ApplicationStreams.md)
to prepare these explicit operator decisions:

1. Enroll a dedicated stable application principal for each cluster. Give it
   action 30 access to the other cluster's service, scoped to that service ID.
2. Register a protocol 7 endpoint route for each cluster. Attached endpoints
   connect outbound through their approved relay and need no public listener.
3. Offer and accept a service whose protocol is exactly `ficc.federation/1`.
   The application owner and endpoint operator sign the exact route, binding,
   limits and expiry. Registration uses action 29 for that service ID.
4. Generate the endpoint configuration with `streams endpoint-config`. Start
   the companion with both `--binding` and `--targets`. Each target names the
   other service, its protocol, connect grant and retained endpoint profile.
5. Use the companion's `Ingress` directory in Core's explicit runtime setup.
   Preview and consent to the endpoint manifest, then activate it normally.
6. Run the companion as the same dedicated Unix account as its FICC controller.
   The SDK directory is private mode 0700; `Control.sock` is mode 0600. The
   mapped ingress helper preserves Core's container isolation and cannot read
   the application's private keys. Do not loosen directory permissions.

The companion can use `network connect --profile ... -- streams agent ...`
with an existing joined profile. It need not own an authority installation.
An endpoint on a separate machine also needs Suite's
`network authority-connector` from its own joined profile. Pass its mapped
`Ingress` directory to Core with `--authority-connector-directory`; keep its
requester profile separate from the application companion.
Route vouchers, service limits and application grants remain independent.
Inspect their finite validity and allowances before selecting transfer sizes.
Size the relay's attachment capacity across both clusters: two endpoints that
each park eight connections need room for at least sixteen attachments. Check
the separate reader capacity for client and authority traffic as well.

Binary FICC packages include the maintained `hypernet-streams` Python SDK.
They do not install, start or silently configure HyperNet. Source installations
can include its wheel with `--hypernet-sdk-wheel PATH --hypernet-sdk-sha256 HASH`.
Obtain the wheel and expected digest from the trusted HyperNetSuite bundle.
Ordinary Python environments can install that verified wheel with
`python -m pip install --no-index --no-deps PATH` before starting FICC.

## Pair and share

Open **Federation**, select **Configure connection**, and enter the cluster
label and companion directory. FICC verifies the companion's network, principal,
service and protocol. Its separate cluster key is generated in private state.
Existing pairings prevent a silent change to the selected identities.

Select **Pair a cluster** and choose an approved companion target. The receiving
operator sees the cluster identity and requested operations. **Review access**
selects exact services, model revisions, machines, lifetime, concurrent requests,
request count and model byte allowance. Approval creates no general cluster or
SSH access. The initiating operator then selects **Complete pairing**. Both
cluster keys prove possession and retain the exact signed acceptance receipt.

Sharing is directional. On the other cluster, **Share local resources** grants
reverse access explicitly. **Refresh remote access** lists current remote
grants; select one to use. The local operator needs the underlying resource
permissions to delegate them, in addition to `federation:manage`.

## Use and manage remote inference

**Browse shared resources** lists only the selected grant's services and models.
Use **Try prompt** and **Cancel request**, or copy the compatible client base URL.
An agent authenticates to its own FICC with a `federation:invoke` project token;
that token is never forwarded. Select a published remote service ID as `model`.

An `inference:manage` grant permits **New remote service** and configuration of
stopped managed services. The model and every machine must be in its grant, or the model must have been
created under that grant's explicit model-management permission.
The form uses the remote cluster's approved runtime offers and resource preview.
Start, drain, stop and remove use the current remote revision. Existing HTTP
endpoint profiles must be attached by a receiving-cluster operator; remote grants
can control an explicitly shared attachment's lifecycle without owning its server.

Each mutation has an operation ID shown before dispatch. Retain that ID. If the
connection breaks, use **Inspect operation** before issuing a new action. Exact
completed retries return the recorded result; a changed request with the same
ID is refused. An uncertain outcome requires inspection on the receiving cluster.
FICC never automatically repeats an uncertain launch on another machine.

## Transfer and retain models

Inspect a published model's immutable revision, licence, file sizes and SHA-256
digests, then choose **Acquire or resume verified copy**. This also requires
local `models:manage` and a remote `models:transfer` grant with sufficient bytes.
Remote manifests contain no upstream download URLs. Upstream acquisition remains
a separate, explicitly selected Models operation.

FICC requests at most 64 MiB per range, across fresh finite HyperNet streams.
Partial bytes remain in the local model cache. Pause, controller restart or
transport interruption preserves the offset; select the same revision to resume.
Transient connection loss permits at most three automatic reconnects per acquisition,
after waits of one, two and four seconds. Each reconnect requests immutable ranges
from the durable offset and rechecks current access. Revoked rights, changed content
and integrity failures stop acquisition. Pause also cancels a reconnect wait.
After that finite retry allowance, select the same revision to resume explicitly.
Only a complete file with the declared full SHA-256 becomes available to an
engine. Repeated bytes consume the remote grant's allowance. A completed model
remains under local retention policy after its peer or grant is removed.

The controller owns its model library; contributors have verified placement
caches. Configure the controller's state/library on appropriate storage before
large acquisition. A remote contributor's disk is not implicitly the controller's
library. Ordinary storage admission and disk reserve checks still apply.

## Revoke and recover

Revocation cancels active operations and prevents further requests under the
grant. Removing a peer also closes outgoing streams and clears its selected
remote grant. Already delegated workloads remain locally managed by default.
The grant's explicit stop-on-revoke option stops only services created by that
grant, even after its credential expires; it does not stop unrelated deployments.
Expiry alone does not silently stop delegated deployments.

After a companion outage, restore its exact accepted identities and route state,
then refresh FICC. Do not weaken binding checks to bypass a mismatch. A backup
restore suspends federation, omits the old private cluster key and clears the
companion binding. Configure the restored controller and pair again explicitly.
Restoring metadata does not restore remote authority.

Status distinguishes missing SDK, unavailable companion, unverified identity,
inactive grants, exhausted quotas and incomplete model copies. A remembered
service state is not proof that it is currently reachable. Review its last
verified time and refresh before acting.

Retained metadata is bounded: 128 peers, 256 offers, 256 grants and 2,048 mutation receipts per controller. Discard unaccepted requests, retire revoked grants or forget removed peers to reclaim capacity. These explicit actions also delete associated operation outcomes; retain any required evidence first. Active grants and their replay protection cannot be pruned.
