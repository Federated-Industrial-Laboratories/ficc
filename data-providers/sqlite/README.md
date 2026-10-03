# Read-only SQLite

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"timeout_seconds":10}
```

Register one controller database file. Queries use :name parameters. SQLite read transactions include journal/WAL state; database-file copies alone are not live snapshots.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
