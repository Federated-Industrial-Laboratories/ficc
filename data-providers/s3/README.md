# S3-compatible objects

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"bucket":"datasets","prefix":"project/","part_bytes":8388608}
```

Approve the HTTPS endpoint, CA, fixed address or DNS allowlist and credential references. Reads pin an object version or SHA-256. Multipart writes bind a dataset and acknowledged part identities; completion includes full-object SHA-256 readback. See the SeaweedFS part-checksum qualification note in the data-source manual.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
