# Typed CSV

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"schema":{"fields":[{"name":"value","type":"integer","nullable":false}]},"encoding":"utf-8","malformed":"error"}
```

Register one controller file. Queries declare columns and filters; malformed schema records fail or are explicitly counted as skipped. This package also provides the CSV encoder.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
