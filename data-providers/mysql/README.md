# MariaDB/MySQL sources

Trusted deployment provider for the installed FICC data SDK. Install the host
first, then this wheel and its pinned dependencies. It is separate from ordinary
workspace modules and from the controller state backend.

Example configuration:

```json
{"database":"measurements"}
```

Approve TLS identity and separate restricted account references. Registered statements use %(name)s parameters. Reads use an unbuffered consistent transaction. Qualify MariaDB and MySQL separately; no universal wire-compatibility claim.

The source distribution contains the complete installation and authority guide at
`docs/data-sources.md`, the contract at `sdk/data-sources.md` and the hashed driver
lock at `data-providers/requirements.lock`. Package license: Apache-2.0. Preserve
the installed dependency distributions and their own license notices.
