# PostgreSQL controller state driver

This optional package implements the FICC state driver interface, version 1.
Install it into a FICC environment that provides this interface. The package can
be installed after the host is built. The host does not import it unless selected.

The driver uses PostgreSQL 18, verified TLS, a dedicated database and one persistent
connection. A database advisory lock prevents concurrent controller ownership.
Connection loss does not trigger reconnection or automatic write replay.

This package runs with controller authority. It is not a sandboxed workspace
module or a job data connector. Install it only from a trusted source.

See `docs/state-storage.md` in the FICC source for configuration, migration,
backup, recovery and the state driver contract. Use `requirements.lock` when
preparing the driver's runtime dependencies.
