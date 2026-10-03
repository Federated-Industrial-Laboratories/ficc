# SPDX-License-Identifier: Apache-2.0
"""Opt-in exact MariaDB/MySQL qualification using dedicated restricted fixtures."""

import asyncio
import datetime
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_files import files_fixture as files_fixture
from test_sources import exported

from ficc.datasets import Datasets
from ficc.errors import Failure
from ficc.secret_cli import initialize
from ficc.secrets import Secrets
from ficc.sources import Sources


def wrong_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted fixture CA")])
    now = datetime.datetime.now(datetime.UTC)
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(
        x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1)).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


@pytest.mark.skipif(not os.environ.get("FICC_SOURCE_FIXTURES"), reason="Dedicated source fixtures are opt-in.")
@pytest.mark.parametrize("family", ["mariadb", "mysql", "postgresql"])
async def test_restricted_sql_tls_export_and_explicit_transaction(files_fixture, family):
    service, actor, root, path = files_fixture
    fixture = Path(os.environ["FICC_SOURCE_FIXTURES"])
    port_value = os.environ.get("FICC_SOURCE_" + family.upper() + "_PORT")
    if not port_value:
        pytest.skip("This dedicated source server is not selected.")
    port = int(port_value)
    initialize(service.settings.state_dir, service.settings.state_dir.parent / "source-key")
    secrets = Secrets(service.settings.state_dir)
    for role in ("reader", "writer"):
        secrets.put(role, (fixture / f"{family}-{role}.json").read_bytes())
    service.datasets = Datasets(service)
    service.sources = Sources(service)
    body = {"name": "Restricted SQL fixture", "provider": "postgresql" if family == "postgresql" else "mysql", "configuration": {"database": "ficc_fixture"},
        "endpoint": {"host": "127.0.0.1", "port": port, "addresses": ["127.0.0.1"], "ca_pem": (fixture / "ca.pem").read_text(), "private_network": True},
        "read_secret": "reader", "write_secret": "writer", "permissions": ["read", "export", "write"]}
    if family == "postgresql":
        body["endpoint"]["ca_pem"] = (fixture / "postgresql-ca.pem").read_text()
        body["endpoint"]["fixed_address"] = "127.0.0.1"
    connection = await service.sources.create(body, "sql-fixture-connection", actor)
    catalogue = await service.sources.inspect(connection["id"], actor, "catalogue", {})
    assert any(item["name"].endswith("readings") for item in catalogue["resources"])
    read = service.sources.register(connection["id"], {"name": "Read", "specification": {"statement": "SELECT id,value FROM readings WHERE id >= %(minimum)s ORDER BY id"},
        "parameters": [{"name": "minimum", "type": "integer"}]}, "sql-fixture-read", actor)
    preview = await service.sources.preview(read["id"], {"minimum": 2}, actor)
    assert preview["rows"] == [[2, 20], [3, 30]] and preview["receipt"]["tls_verified"]
    if family != "postgresql":
        assert preview["receipt"]["server_family"] == family
    else:
        assert preview["receipt"]["snapshot"]
    result = await exported(service, actor, root, read, {"minimum": 2}, family + "-result")
    assert result["state"] == "completed", result
    assert (path / (family + "-result.csv")).read_text() == "id,value\n2,20\n3,30\n"
    literal = service.sources.register(connection["id"], {"name": "Literal", "specification": {"statement": "SELECT %(value)s AS value"},
        "parameters": [{"name": "value", "type": "string"}]}, "sql-fixture-literal", actor)
    attack = "'; UPDATE readings SET value=999; --"
    assert (await service.sources.preview(literal["id"], {"value": attack}, actor))["rows"] == [[attack]]
    denied = service.sources.register(connection["id"], {"name": "Forbidden read mutation", "specification": {"statement": "UPDATE readings SET value=999 WHERE id=1"}}, "sql-fixture-denied", actor)
    with pytest.raises(Failure):
        await service.sources.preview(denied["id"], {}, actor)
    write = service.sources.register(connection["id"], {"name": "Explicit write", "mode": "write", "specification": {"statement": "UPDATE readings SET value=%(value)s WHERE id=1"},
        "parameters": [{"name": "value", "type": "integer"}]}, "sql-fixture-write", actor)

    async def set_value(value):
        run = await service.sources.submit(write["id"], {"action": "write", "parameters": {"value": value}}, "sql-fixture-write-" + str(value), actor)
        await asyncio.gather(*list(service.sources.tasks.values()))
        saved = service.sources.status(run["id"], actor)
        assert saved["state"] == "completed" and saved["receipt"]["outcome"] == "committed", saved
    try:
        await set_value(11)
        assert (await service.sources.preview(read["id"], {"minimum": 1}, actor))["rows"][0] == [1, 11]
    finally:
        await set_value(10)
    for index, change in enumerate(({"host": "localhost", "addresses": ["127.0.0.1", "::1"]}, {"ca_pem": wrong_ca()})):
        invalid = await service.sources.create({**body, "endpoint": {**body["endpoint"], **change}}, "sql-fixture-tls-" + str(index), actor)
        with pytest.raises(Failure):
            await service.sources.inspect(invalid["id"], actor, "catalogue", {})
    assert (await service.sources.preview(read["id"], {"minimum": 1}, actor))["rows"] == [[1, 10], [2, 20], [3, 30]]
    assert service.datasets.get(result["dataset_id"], actor)["origin"]["receipt"]["tls_verified"]
