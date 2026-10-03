# Parquet and Arrow

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"format":"parquet"}
```

Register one Parquet file or Arrow IPC stream. Queries declare columns and filters. Parquet projection is pushed into the reader; filters run on record batches. This package supplies Arrow IPC and Parquet encoders.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
