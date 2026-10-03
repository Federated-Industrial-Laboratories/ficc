# Local encrypted secrets

`ficc-secret-local` supplies the `local` entry point in `ficc.secret`. Install this
trusted runtime package into the controller environment after installing FICC:

```sh
python -m pip install --no-deps ficc_secret_local-0.2.5-py3-none-any.whl
```

It uses the controller's pinned `cryptography==50.0.2` dependency. Records use
AES-256-GCM with random 96-bit nonces and full 128-bit authentication tags.
Store identity, reference and revision are authenticated along with the value.
Atomic owner-only writes sync the record and its directory. A private lock
serializes compare-and-swap updates and deletion.

The 32-byte key is a separately managed private file outside controller state.
Configuration and encrypted records live under `secrets-private/`, which normal
FICC state backup excludes. Missing keys, modified ciphertext, insecure file
permissions and incorrect keys fail closed. Keys and plaintext are not cached
between operations; Python does not guarantee memory erasure.

See [secret administration](../../docs/secrets.md) for setup, migration and
recovery, and the [provider contract](../../sdk/secrets.md) for integration.
This package encrypts secret records only. It does not encrypt state, working
data, swap or backups, resist an administrator controlling the process, or
detect rollback to an older authenticated vault copy.
