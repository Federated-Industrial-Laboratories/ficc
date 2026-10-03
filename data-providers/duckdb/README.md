# Optional local analytics

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"format":"parquet","memory_bytes":134217728}
```

Register one Parquet or Arrow IPC input, exposed as source. Registered SELECT statements use $name parameters. External access, automatic extensions, replacement scans and spill are disabled. The dedicated worker closes the implicit default DuckDB connection and uses a one-thread connection.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
