# SPDX-License-Identifier: Apache-2.0
"""Own a verified PostgreSQL connection and refuse ambiguous write retries."""

import ipaddress
import re
from itertools import islice
from pathlib import Path

from sqlalchemy import URL, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import NullPool

from ficc.state_provider import StorageFailure, read_private

from .schema import initialize as initialize_schema

API_VERSION = 1
LOCK = 70750701


def host_name(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return len(value) <= 253 and bool(re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?", value))


def connect(configuration, binding, *, initialize=True):
    return Database(configuration, binding, initialize=initialize)


class Database:
    def __init__(self, config, binding, *, initialize):
        required = {"host", "port", "database", "user", "password_file", "ca_file"}
        if (not isinstance(config, dict) or set(config) - required - {"hostaddr"} or required - set(config)
                or any(not isinstance(config[key], str) or not config[key] for key in required - {"port"})
                or type(config["port"]) is not int or not 1 <= config["port"] <= 65535
                or "hostaddr" in config and not isinstance(config["hostaddr"], str)):
            raise ValueError("The PostgreSQL connection settings are invalid.")
        if not host_name(config["host"]):
            raise ValueError("Select one DNS host name or IP address for verified database TLS.")
        if "hostaddr" in config:
            try:
                ipaddress.ip_address(config["hostaddr"])
            except ValueError:
                raise ValueError("The database host address must be one IP address.") from None
        if not Path(config["password_file"]).is_absolute():
            raise ValueError("Select an absolute path for the database password file.")
        password = read_private(Path(config["password_file"]), 4096).decode().removesuffix("\n")
        ca = Path(config["ca_file"])
        if not ca.is_absolute() or not ca.is_file() or not password:
            raise ValueError("Select a readable certificate authority and a private database password file.")
        options = {"sslmode": "verify-full", "gssencmode": "disable", "sslrootcert": str(ca), "connect_timeout": 5,
                   "application_name": "ficc-state",
                   "options": "-c search_path=public -c statement_timeout=15000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000"}
        if "hostaddr" in config:
            options["hostaddr"] = config["hostaddr"]
        url = URL.create("postgresql+psycopg", username=config["user"], password=password,
                         host=config["host"], port=config["port"], database=config["database"])
        self.engine = create_engine(url, connect_args=options, poolclass=NullPool,
                                    isolation_level="AUTOCOMMIT", hide_parameters=True)
        self.connection = None
        self.failed = False
        self.active = False
        self.depth = 0
        self.rollback_only = False
        try:
            self.connection = self.engine.connect()
            transport = self.connection.connection.driver_connection
            if transport is None or not transport.pgconn.ssl_in_use:
                raise StorageFailure("The database connection did not establish verified TLS.")
            if not self.connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK}).scalar_one():
                raise ValueError("Another controller or maintenance command owns this database.")
            self.begin()
            initialize_schema(self.connection, binding, create=initialize)
            self.commit()
        except BaseException as exc:
            self.close()
            if isinstance(exc, SQLAlchemyError):
                raise StorageFailure("The verified state database connection failed.") from None
            raise

    def _ready(self):
        if self.failed or self.connection is None:
            raise StorageFailure("The state connection was lost. Restart after checking database ownership and pending writes.")
        return self.connection

    def begin(self):
        if self.active:
            raise StorageFailure("A state transaction is already active.")
        try:
            self._ready().exec_driver_sql("BEGIN")
            self.active = True
        except SQLAlchemyError:
            self.failed = True
            raise StorageFailure("The state transaction could not start.") from None

    def execute(self, statement, parameters=()):
        try:
            operation = statement.lstrip().split(None, 1)[0].upper()
            if operation not in {"SELECT", "INSERT", "UPDATE", "DELETE"}:
                raise StorageFailure("Use the state provider schema interface for structural changes.")
            if operation != "SELECT" and not self.active:
                self.begin()
            values = parameters if isinstance(parameters, dict) else {f"p{i}": value for i, value in enumerate(parameters)}
            return self._ready().execute(text(statement), values)
        except BaseException as exc:
            self.rollback_only = self.active
            if getattr(exc, "connection_invalidated", False):
                self.failed = True
            if isinstance(exc, SQLAlchemyError):
                raise StorageFailure("The state operation failed. No write was retried.") from None
            raise

    def executemany(self, statement, parameters):
        result = None
        try:
            if statement.lstrip().split(None, 1)[0].upper() not in {"INSERT", "UPDATE", "DELETE"}:
                raise StorageFailure("A batched state operation must be a record mutation.")
            rows = iter(parameters)
            while batch := list(islice(rows, 128)):
                if not self.active:
                    self.begin()
                values = [row if isinstance(row, dict) else {f"p{i}": value for i, value in enumerate(row)} for row in batch]
                result = self._ready().execute(text(statement), values)
        except BaseException as exc:
            self.rollback_only = self.active
            if getattr(exc, "connection_invalidated", False):
                self.failed = True
            if isinstance(exc, SQLAlchemyError):
                raise StorageFailure("The batched state operation failed. No write was retried.") from None
            raise
        return result

    def commit(self):
        if self.depth:
            return
        try:
            if self.rollback_only:
                self.rollback()
                raise StorageFailure("The state transaction was rolled back after an earlier failure.")
            self._ready().commit()
            self.active = False
        except SQLAlchemyError:
            self.failed = True
            raise StorageFailure("The state commit outcome is unknown. No write was retried.") from None

    def rollback(self):
        try:
            self._ready().rollback()
            self.active = False
            self.rollback_only = False
        except SQLAlchemyError:
            self.failed = True
            raise StorageFailure("The state connection failed during rollback.") from None

    def __enter__(self):
        if not self.active:
            self.begin()
        self.depth += 1
        return self

    def __exit__(self, kind, value, traceback):
        self.depth -= 1
        if kind is not None:
            self.rollback_only = True
        if self.depth == 0:
            if kind is not None:
                self.rollback()
            else:
                self.commit()

    def table_names(self):
        return {row[0] for row in self.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public'")}

    def snapshot(self, destination):
        from .portability import snapshot
        try:
            snapshot(self, destination)
        except SQLAlchemyError:
            self.failed = True
            raise StorageFailure("The controller snapshot failed. No write was retried.") from None

    def import_snapshot(self, source):
        from .portability import import_snapshot
        try:
            return import_snapshot(self, source)
        except SQLAlchemyError:
            self.failed = True
            raise StorageFailure("The state import failed. Check its durable receipt before resuming.") from None

    def close(self):
        connection, self.connection = self.connection, None
        try:
            if connection is not None:
                connection.close()
        finally:
            self.engine.dispose()
