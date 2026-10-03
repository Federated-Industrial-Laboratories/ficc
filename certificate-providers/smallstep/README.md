# Smallstep certificate provider

This package connects FICC's approved node requests to a private Smallstep CA.
Install it separately from the controller. Select the `smallstep` entry point
in the trusted `ficc.certificates` provider configuration.

The provider implements certificate interface version 1. It accepts Ed25519 and
ECDSA P-256 node keys. A signed request must contain one node URI and its node
ID as the common name. Extra request extensions are rejected.

The node keeps its private key. FICC approves the request before calling this
provider. FICC also checks returned certificates and controls current node access.
Ordinary panel grants cannot install certificate providers or change this trust.

## Install

Use Python 3.12 or later. The tested dependencies are cryptography 50.0.2,
joserfc 1.7.5 and HTTPX 0.28.1. `requirements.lock` pins their dependency closure
and artifact hashes. Install into the controller's private Python environment:

```sh
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps .
```

The supplied CA profile requires step-ca 0.30.2. Its setup commands use step CLI
0.31.0. Obtain these from the official releases and verify their published checksums
or Sigstore signatures before installation:

- [step-ca 0.30.2](https://github.com/smallstep/certificates/releases/tag/v0.30.2)
- [step CLI 0.31.0](https://github.com/smallstep/cli/releases/tag/v0.31.0)

This package does not download, start or administer a production CA automatically.

## Provider configuration

Store this object in the private installation configuration:

```json
{
  "ca_url": "https://localhost:9000",
  "installation_id": "0123456789abcdef0123456789abcdef",
  "provisioner": "ficc-nodes",
  "signing_key_file": "/etc/ficc/certificates/provisioner.json",
  "root_file": "/etc/ficc/certificates/root_ca.crt",
  "request_seconds": 15
}
```

Use the real immutable installation ID. The endpoint must be an explicit HTTPS
origin without a path, query, user information or fragment. Only `/sign` and
`/revoke` are used. Environment proxies, redirects and remote key URLs are disabled.
The supplied root file is the exclusive TLS and certificate trust source.

The signing file contains a P-256 private JWK, its `kid`, and ES256 signing use.
It must be a regular file owned by root or the controller account, with mode 0600.
The provider rejects links, unsafe ancestors, extra hard links and changed files.
Public trust files can be readable by other accounts but cannot be writable by them.
Use separate accounts for the controller and CA. Restart the provider after an
administrator replaces its signing credential or trust roots.

Four network requests can run concurrently. Additional calls fail promptly.
The configured elapsed request limit is 1 to 15 seconds, including the response.
HTTP responses are limited to 64 KiB. Certificate chains are limited to 16 KiB.
Errors contain fixed text and do not include tokens, private keys or response bodies.

## Create the authority

Perform initial CA creation on the offline root workstation. Use an encrypted root
key and a separate encrypted intermediate key. Keep passwords in private files
or use the CLI's terminal prompts. Never put passwords in command arguments.

For example, set `STEPPATH` to a new private directory, then use `step ca init`
with `--deployment-type=standalone`, `--name`, `--dns=localhost`,
`--dns=127.0.0.1`, `--address=127.0.0.1:9000` and `--password-file`.
The generated bootstrap provisioner is replaced by the supplied profile.
Keep `secrets/root_ca_key` offline. Transfer only the public root, public
intermediate and encrypted intermediate key to the CA account.

Create a separate P-256 JWK for the controller. `step crypto jwk create` can
generate the public and private JWK files. Its default private file is encrypted.
For an unattended controller, create a private unencrypted copy with the CLI's
`--no-password --insecure` options inside the controller's mode 0700 directory.
Protect that file with mode 0600 and an encrypted system disk. Do not transfer
the root or intermediate private key to the controller.

Generate the CA configuration from public inputs:

```sh
umask 077
python deployment/profile.py \
  --directory /var/lib/ficc-node-ca \
  --public-jwk /etc/ficc-node-ca/provisioner-public.json \
  --installation-id 0123456789abcdef0123456789abcdef \
  --output /etc/ficc-node-ca/ca.json
```

The output must not exist. The profile uses these paths:

| File | Account | Mode |
| --- | --- | --- |
| `/var/lib/ficc-node-ca/certs/root_ca.crt` | CA account | 0600 |
| `/var/lib/ficc-node-ca/certs/intermediate_ca.crt` | CA account | 0600 |
| `/var/lib/ficc-node-ca/secrets/intermediate_ca_key` | CA account | 0600 |
| `/etc/ficc-node-ca/intermediate-password` | CA account | 0600 |
| `/etc/ficc-node-ca/ca.json` | root, CA group | 0640 |
| `/etc/ficc-node-ca/provisioner-public.json` | root, CA group | 0640 |

Use mode 0700 for the CA state and its child directories. Use root ownership,
the CA group and mode 0750 for `/etc/ficc-node-ca`. Apply `chmod` explicitly after
creating directories: a restrictive umask also removes requested group access.
The root private key must be absent from the CA service account and directory.

Install `deployment/ficc-node-ca.service` after setting its executable path and
creating the `ficc-node-ca` system account. The service binds loopback only.
It has two CPU cores, a 512 MiB memory limit and a 64-task limit. Its database
is writable only below the private state directory. Use a distinct authority
and intermediate for FICC nodes; do not reuse identity-service backend keys.

The supplied template binds its node URI to the installation and token subject.
It requires the token's native `cnf.x5rt#S256` CSR fingerprint binding. It emits
client authentication use, digital signatures and no CA authority. It accepts
only Ed25519 or P-256 keys. The provisioner permits 60-second to 24-hour leaves.
The provider submits exact validity dates for the requested lifetime. The profile
sets authority backdating to zero, including at the 60-second lower bound.
Keep controller and CA clocks synchronized before admitting nodes.

The profile deliberately omits Smallstep's optional HTTP request logger, which
records authorization tokens. Do not enable raw request or body logging in a
proxy. Keep CA process health logs and FICC's credential-free audit records.

## Rotation, revocation and recovery

Direct Smallstep certificate renewal is disabled. A node creates a new key and
passes through FICC's rotation and activation checks. Each signing authorization
has a fresh random token ID, a 60-second lifetime and one exact CSR binding.
The authority database enforces single use. Preserve that database across restarts.

Revocation supports `superseded`, `disabled` and `recovery`. A repeated revoke
is accepted only when the verified authority returns its exact already-revoked
response for the same serial. An error does not undo FICC's immediate denial.
The CA generates signed CRLs, but passive revocation does not close existing TLS
connections. FICC must check registered certificate status for every node action.

The provider never retries a mutation automatically. A timeout, disconnect or
invalid response can leave an uncertain CA result. FICC must leave that result
unregistered. A separate explicit attempt can issue another certificate; only
FICC's exact active certificate receives authority. Revocation can be repeated
explicitly after an uncertain result.

Back up the CA database, public chain, configuration and encrypted intermediate
separately from controller state. Keep the root and its recovery material offline.
Before restoring CA state, stop node admission and reconcile FICC's revocations;
an older CA database can forget revocation and used-token records. Do not restore
node authority automatically from either backup. Check intermediate expiry before
it prevents the requested leaf lifetime. Root recovery and intermediate rotation
require an installation administrator.

## Checks

Install the pinned dependencies and pytest. Supply paths to the verified tools:

```sh
export FICC_TEST_STEP=/opt/step/bin/step
export FICC_TEST_STEP_CA=/opt/step/bin/step-ca
PYTHONPATH=src python -m pytest -q
```

Tests create a disposable loopback CA with synthetic keys. The root key is moved
out of its online directory before startup. Distinct-node checks run at N=1 and
N=64. HTTPS fault tests forward real CA mutations, then alter or lose responses.
These checks do not replace deployment checks for accounts, service confinement,
gateway certificates, host approval, node leases or recovery.

Source references:

- [Certificate templates](https://smallstep.com/docs/step-ca/templates/)
- [JWK CSR binding](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/jwk.go)
- [Revocation behavior](https://smallstep.com/docs/step-cli/reference/ca/revoke/)
- [JWT signing](https://jose.authlib.org/en/guide/jwt/)
- [Certificate verification](https://cryptography.io/en/latest/x509/verification/)
