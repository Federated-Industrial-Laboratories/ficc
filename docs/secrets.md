# Secret references

Source connections store references to credentials, not credential values.
The reusable host secret service resolves those references through a separately
installed trusted provider. The supplied `ficc-secret-local` package encrypts
records with AES-256-GCM using the established `cryptography` implementation.
Its authenticated encryption detects modified ciphertext and incorrect keys.
See the [upstream AESGCM documentation](https://cryptography.io/en/50.0.2/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).

There is no secret-value API, browser field, display command or argument option.
Administration runs locally as the controller account. Commands print only
references, revisions and operation status. References contain 1 to 80 letters,
digits, underscores, dots or hyphens, beginning with a letter or digit. Values
are opaque bytes, limited to 32 KiB per record. Source credentials must also
match the JSON format in [data sources](data-sources.md).

## Install and initialize

Install the runtime wheel after the host wheel, in the same Python environment:

```sh
python -m pip install --no-deps ficc_secret_local-0.2.5-py3-none-any.whl
install -d -m 700 "$HOME/.config/ficc-secret-keys"
ficc secret-init --state-dir "$HOME/.local/state/ficc" \
  --key-file "$HOME/.config/ficc-secret-keys/controller.key"
ficc secret-status --state-dir "$HOME/.local/state/ficc"
```

Stop the controller for initialization, provider configuration and legacy
migration; these commands require exclusive state ownership. Ordinary put,
status and delete operations use the provider's own concurrency control and can
run while the controller is active.

The key file must not already exist. Initialization creates a random 32-byte key
with mode 0600. Its existing parent must have mode 0700. The key must be outside
controller state, registered file roots, worker mounts and normal backup trees.
Protect it with a separate access and recovery policy. No key material is placed
in controller settings or environment variables. Configuration and ciphertext
live in `STATE/secrets-private/`; files have mode 0600 and directories mode 0700.

## Create, rotate and delete

Prepare the credential using an owner-controlled tool in a private directory.
The input file must be owned by the controller account, mode 0600 or stricter,
with one link and no symlink components. This example reads an existing file:

```sh
ficc secret-put --state-dir "$HOME/.local/state/ficc" \
  --reference warehouse-reader --input "$HOME/.config/private-inputs/reader.json"
ficc secret-status --state-dir "$HOME/.local/state/ficc" \
  --reference warehouse-reader
```

`--input -` reads bounded non-terminal stdin. Interactive terminal input is
refused so credentials are not echoed. Never place a secret in shell arguments
or command history. FICC does not remove ordinary input files; their lifecycle
belongs to the administrator.

Creation refuses an existing reference. To rotate it, pass `--revision` with the
current 64-character revision returned by status. The same reference then gets
a new revision, even if its bytes are unchanged. Existing source approvals bind
the previous revision and fail closed until a newly approved connection uses
the current one. Deletion also requires the current revision:

```sh
ficc secret-delete --state-dir "$HOME/.local/state/ficc" \
  --reference warehouse-reader --revision CURRENT_REVISION
```

Rotation blocks new dispatches through the old approval. Already dispatched
workers can retain their credential until that operation ends; cancel affected
work and revoke the upstream credential when immediate revocation is required.

Deletion removes the local record; revoke or rotate the upstream account as
appropriate. It does not erase filesystem snapshots or guarantee secure media
erasure. If a mutation's outcome is uncertain, inspect status before another
mutation. A conflict requires the current revision and an explicit decision.

## Migrate previous source credentials

Older installations used plaintext JSON at `STATE/data-secrets/REFERENCE`.
Private mode bits did not encrypt those files. Resolution now requires the
secret provider and never falls back to those plaintext files.

After initializing the provider, explicitly migrate each reference:

```sh
ficc secret-migrate-source --state-dir "$HOME/.local/state/ficc" \
  --reference warehouse-reader --remove-plaintext
```

Migration reads the original bytes and original controller revision key. It
preserves the reference and its HMAC revision, so existing source approvals stay
bound to exactly the same credential. It authenticates the stored encrypted
copy before removal. Without `--remove-plaintext`, the result explicitly reports
`plaintext_retained: true`. Repeating a migration while the original remains
reconciles the same encrypted bytes and revision; a different record conflicts.
If a removed source has no acknowledgement, inspect the encrypted reference
with status. Do not recreate plaintext simply to retry the command.

## Recovery and limits

Normal state export excludes the entire `secrets-private/` directory and legacy
`data-secrets/`. The external key is also absent. A restored controller can retain
secret references but cannot use them until the appropriate store is restored.
This is deliberate: a portable state backup must not also deliver credentials.

Maintain a separate protected copy of the encrypted `secrets-private/` directory
and independent recovery custody for the master key. Stop secret mutations while
copying it. Restore the directory under the intended state directory with its
private permissions, and restore the original key to its configured path. Run
`secret-status` and check the metadata of required references before reconnecting
sources. A missing, wrong or insecure key is never regenerated automatically.
Losing the only key makes the ciphertext unrecoverable; provision new credentials
and approve new source connections instead.

If only provider configuration is missing, `secret-init --existing-key` can
rebind the retained local records to the supplied original key after validating
their encrypted store check. It never replaces a key or existing configuration.
Other installed providers use `secret-configure --input PRIVATE_CONFIG` with
`{"provider":"NAME","configuration":{...}}`; see the
[runtime contract](../sdk/secrets.md).

This provider encrypts secret records, not controller state, workload data,
temporary source input files, swap, core dumps or unrelated backups. Use approved
OS/storage encryption for those. Authorized controller and worker processes
necessarily receive plaintext. Python does not promise key-memory erasure.
An administrator controlling those processes or holding both key and ciphertext
can read the secrets. Authentication does not detect rollback to an older valid
record; retain current revision approvals and revoke upstream credentials after
a compromise. Restoring the key and vault is not an upstream credential rotation.
