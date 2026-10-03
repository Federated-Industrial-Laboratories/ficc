# Controller state storage

SQLite remains the default state database. It needs no network driver.
The PostgreSQL driver stores the same controller records on a database server.
Both backends support controller schema 15, including project datasets, source
operations, dataset safety, lineage and inspection receipts.
The controller still needs its private local state directory for module files,
receipts, locks and the binding to its database.

One controller or maintenance command owns a database at a time.
The PostgreSQL driver holds a connection-level advisory lock for this ownership.
This provides exclusive ownership, not a replicated controller or automatic failover.
Use a dedicated database and role for each controller. Keep the controller and
database close to each other to limit query latency.

## Install a driver

State drivers are trusted installation components. They run inside the controller
and can access all its state. They are separate from sandboxed workspace modules
and from data connectors used by jobs. Ordinary module grants cannot install or
select a state driver.

The v0.2.5 source installer and binary payload include the separately built
PostgreSQL wheel and its locked dependencies among the
[17 supplied runtime providers](dependencies.md#supplied-runtime-providers).
SQLite stays selected until an administrator configures another backend.
For a host-only wheel installation, install the PostgreSQL wheel and its
dependencies into the controller's Python environment. A host rebuild is not
required. The source package is in `state-providers/postgresql/`. Install only
drivers from a trusted source and use the supplied dependency lock.

The current driver supports PostgreSQL 18 and upgrades controller schemas 7
through 14 to schema 15 in one transaction while holding database ownership.
Keep a stopped pre-upgrade backup; an older controller cannot open schema 15.
Source databases are separate from this private controller state store. A database
account needs ownership of its dedicated database schema, tables and sequences.
It does not need superuser status, role creation or database creation permission.
Do not grant application users direct access to the state database.

## Configure a new controller

Prepare a private JSON file with this structure:

```json
{
  "provider": "postgresql",
  "configuration": {
    "host": "database.example.com",
    "port": 5432,
    "database": "ficc_controller",
    "user": "ficc_controller",
    "password_file": "/home/operator/.config/ficc/database-password",
    "ca_file": "/home/operator/.config/ficc/database-ca.pem"
  }
}
```

The configuration and password files must have mode `0600`, belong to the current
account, and be regular files with one link. Symlinks are refused. Use absolute
paths for the password and certificate authority files. The password is read from
its file; do not put it in the JSON, shell arguments or connection URLs.

TLS certificate and hostname verification are required. There is no option to
disable verification. Select one DNS host name or IP address. Socket paths and
multi-host fallback lists are refused. The driver requires an actual TLS channel
and disables GSS encryption negotiation, which libpq can otherwise prefer to TLS.
The optional `hostaddr` setting selects one IP address
while `host` remains the certificate name. This also supports a separately
configured SSH tunnel with end-to-end database TLS verification.

Run the following command with a new private state directory and an empty database:

```sh
ficc state-configure --state-dir /home/operator/.local/state/ficc-remote \
  --input /home/operator/.config/ficc/state-provider.json
```

Start FICC with that state directory. Its `state-provider.json` selects the driver.
Its `state-binding` connects local files to the database. Keep both files private.
Copying the configuration alone cannot attach a different state directory.
Database connection failures return a redacted storage error.

## Migrate an existing controller

Stop the controller and ensure remote work is idle. Keep the source state intact.
Select a new destination directory and an empty PostgreSQL database:

```sh
ficc state-migrate --state-dir /home/operator/.local/state/ficc \
  --input /home/operator/.config/ficc/state-provider.json \
  --output /home/operator/.local/state/ficc-remote --confirm-remote-idle
```

Migration uses the portable export and restore checks. It preserves records and
module files, removes credentials, disables restored users other than the local
owner, and clears module grants. Review authority and issue fresh credentials
before enabling work. The source controller is unchanged; keep it stopped while
using the migrated installation.

The destination retains its portable database until the network import commits.
An interrupted final cleanup leaves startup blocked. Resume that exact import:

```sh
ficc state-migrate --state-dir /home/operator/.local/state/ficc-remote --resume
```

A durable database receipt identifies the imported snapshot. Resume refuses a
different snapshot and does not repeat a committed import. Do not remove the local
portable database to bypass a pending migration.

## Backup and failure recovery

The stopped-controller export creates a portable SQLite bundle from either
backend. Provider configuration, passwords and the local binding are excluded.
Restore creates an isolated local SQLite controller with authority disabled as
described in [Backup and recovery](backup.md). Network database dumps alone do not
include local module files and receipts; retain a complete controller backup.
Dataset files, external source data, scanner assets, the encrypted secret store
and its key, and audit destination custody need their own recovery procedures.
Metadata backup preserves dataset restrictions and receipts, while restore
revokes exemptions and suspends source and scanner approvals. Reconfigure them
before resuming work; retained metadata does not prove those external bytes exist.

History archival holds database ownership through remote acknowledgements and
the controller commit. A second controller or maintenance command is refused.
If a connection is lost, the driver does not reconnect or retry writes. Stop the
controller, check database ownership and pending operation receipts, and restart
after the database is available. A lost commit response has an unknown outcome;
do not assume the operation failed or submit it again with a new command key.

## State driver interface

Drivers register one `ficc.state` entry point whose name matches `provider`.
The entry-point module exports `API_VERSION = 1` and
`connect(configuration, binding, initialize=True)`. Duplicate registrations and
unsupported interface versions are refused.

The returned object supplies `execute`, `executemany`, `begin`, `commit`,
`rollback`, `close`, transaction context management, `table_names`,
`snapshot(destination)` and `import_snapshot(source)`.
Shared record SQL uses named `:p0`, `:p1` parameters. A positional parameter
sequence binds in that order; dictionaries retain their explicit names.
Nested transactions commit only at the outer boundary. Parameter iteration,
binding, statement and inner transaction failures mark the outer transaction for
rollback even when the caller catches the exception.

The driver owns its schema, transport verification and exclusive database lock.
It must preserve record uniqueness, insertion order where required, binary module
manifests, numeric values and durable identity fields. Snapshot output must pass
the current portable schema and quiescence checks. Import must be atomic, refuse
nonempty state, and record its snapshot receipt in the same transaction.
Lost ownership must prevent all further reads and writes on that connection.

The PostgreSQL package is the reference implementation. Run the maintained
storage conformance tests and real database failure tests before qualifying
another driver. Registration alone does not declare support.
