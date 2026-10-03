# SPDX-License-Identifier: Apache-2.0
"""Prepare disposable state databases from an explicit qualification configuration."""

import json
import os
from pathlib import Path

import pytest

from ficc.state_provider import read_private


def postgres_configuration():
    source = os.environ.get("FICC_TEST_POSTGRES")
    if not source:
        pytest.skip("Set FICC_TEST_POSTGRES to a private disposable PostgreSQL configuration.")
    value = json.loads(read_private(Path(source)))
    config = value["configuration"]
    if value["provider"] != "postgresql" or not config["database"].startswith("ficc_test_"):
        pytest.fail("The qualification database name must start with ficc_test_.")
    return value


def postgres_admin(value):
    import psycopg
    config = value["configuration"]
    return psycopg.connect(host=config["host"], hostaddr=config.get("hostaddr"), port=config["port"],
                           dbname=config["database"], user=config["user"],
                           password=read_private(Path(config["password_file"])).decode().removesuffix("\n"),
                           sslmode="verify-full", sslrootcert=config["ca_file"], autocommit=True, connect_timeout=5)


def reset_postgres(value):
    from psycopg import sql
    with postgres_admin(value) as connection:
        active = connection.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()").fetchone()[0]
        if active:
            pytest.fail("Close other connections before resetting the disposable qualification database.")
        connection.execute("DROP SCHEMA public CASCADE")
        connection.execute(sql.SQL("CREATE SCHEMA public AUTHORIZATION {}").format(sql.Identifier(value["configuration"]["user"])))


def write_provider(state, value):
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = state / "state-provider.json"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output)


@pytest.fixture(params=["sqlite", "postgresql"])
def storage_state(tmp_path, request):
    state = tmp_path / "state"
    if request.param == "postgresql":
        value = postgres_configuration()
        reset_postgres(value)
        write_provider(state, value)
    return state


@pytest.fixture
def postgres_config():
    value = postgres_configuration()
    reset_postgres(value)
    return value
