# Data runtime packages

Install selected trusted deployment wheels into the host environment after the
host wheel. An absent optional package leaves only that provider unavailable.
See [the user workflow](../docs/data-sources.md) and [SDK](../sdk/data-sources.md).

| Directory | Entry point | Driver |
| --- | --- | --- |
| `sqlite` | `sqlite` | Python SQLite; read-only local transaction. |
| `csv` | `csv`; format `csv` | Python CSV; explicit schema and streaming encoder. |
| `postgresql` | `postgresql` | psycopg 3.3.6; TLS/cursors/transactions. |
| `mysql` | `mysql` | PyMySQL 1.1.2, cryptography 50.0.2; MariaDB/MySQL. |
| `arrow` | `arrow`; formats `arrow`, `parquet` | PyArrow 25.0.1; columnar readers/encoders. |
| `s3` | `s3` | boto3 1.43.104, botocore 1.43.108; objects/multipart. |
| `duckdb` | `duckdb` | Optional DuckDB 1.5.6/PyArrow 25.0.1; local read-only analytics. |

From the source distribution with the installed host environment active:

```sh
python -m pip install --require-hashes -r data-providers/requirements.lock
for provider in sqlite csv postgresql mysql arrow s3 duckdb; do
    python -m build --no-isolation "data-providers/$provider"
    python -m pip install --no-deps "data-providers/$provider"/dist/*.whl
done
```

The shared lock installs the complete driver set; deployments may select only
needed packages and pinned dependencies. SQLite/CSV need no extra driver. Keep
wheels and hashes with deployment records. Packages are Apache-2.0. Dependencies
retain their licenses: psycopg LGPL-3.0, PyMySQL MIT, cryptography Apache-2.0/BSD-3-Clause,
PyArrow and boto3/botocore Apache-2.0, DuckDB MIT. Server licenses are separate.

Packages do not start database/object servers. They require approved source
identity, TLS and credential references. Network drivers have one scoped secret
and the host network namespace; their code is trusted to obey endpoint approval.
Local drivers have no network access. SQL account grants enforce actual rights.

Local contracts are in `tests/python/test_sources.py`; dedicated server/S3 checks
are opt-in. Passing one server version does not qualify every implementation
sharing its protocol. Check SDK changes against built, separately installed wheels.
