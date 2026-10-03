# SPDX-License-Identifier: Apache-2.0
"""Detect partial commits and ambiguous commit replay across controller batches."""

import sqlite3

import pytest
from state_fixtures import write_provider

from ficc.state_provider import StorageFailure
from ficc.store import Store


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_caught_statement_failure_rolls_back_complete_batch(storage_state, count):
    store = Store(storage_state / "state.sqlite3")
    try:
        for index in range(count):
            store.set_setting(f"control-{index}", {"value": index})
        with pytest.raises(StorageFailure, match="rolled back"):
            with store.db:
                store.db.executemany("INSERT INTO settings VALUES (:p0,:p1)",
                                     [(f"new-{index}", str(index)) for index in range(count)])
                try:
                    store.db.execute("INSERT INTO settings VALUES ('control-0','null')")
                except sqlite3.Error:
                    pass
        for index in range(count):
            assert store.get_setting(f"new-{index}", None) is None
            assert store.get_setting(f"control-{index}", None) == {"value": index}
    finally:
        store.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
@pytest.mark.parametrize("failure", ["parameters", "batch_row", "iteration", "statement"])
def test_caught_python_statement_failure_rolls_back_on_reopen(storage_state, count, failure):
    store = Store(storage_state / "state.sqlite3")
    def rows():
        for index in range(count):
            yield (f"new-{index}", str(index))
        if failure == "iteration":
            raise ValueError("injected parameter iterator failure")
        yield None
    try:
        for index in range(count):
            store.set_setting(f"control-{index}", {"value": index})
        with pytest.raises(StorageFailure, match="rolled back"):
            with store.db:
                for index in range(count):
                    store.db.execute("UPDATE settings SET value=:p0 WHERE key=:p1", ("null", f"control-{index}"))
                try:
                    if failure == "parameters":
                        store.db.execute("INSERT INTO settings VALUES (:p0,:p1)", None)
                    elif failure == "statement":
                        store.db.execute(None)
                    else:
                        store.db.executemany("INSERT INTO settings VALUES (:p0,:p1)", rows())
                except (TypeError, ValueError, AttributeError):
                    pass
                else:
                    pytest.fail("The malformed statement call did not fail.")
    finally:
        store.close()
    reopened = Store(storage_state / "state.sqlite3")
    try:
        for index in range(count):
            assert reopened.get_setting(f"new-{index}", None) is None
            assert reopened.get_setting(f"control-{index}", None) == {"value": index}
    finally:
        reopened.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_lost_commit_response_retains_effects_without_retry(tmp_path, postgres_config, monkeypatch, count):
    from sqlalchemy.exc import SQLAlchemyError
    state = tmp_path / "state"
    write_provider(state, postgres_config)
    store = Store(state / "state.sqlite3")
    calls = []
    try:
        for index in range(count):
            store.set_setting(f"control-{index}", {"value": index})
        commit = store.db.connection.commit
        def lost_response():
            commit()
            calls.append("committed")
            raise SQLAlchemyError("injected lost commit response")
        with monkeypatch.context() as patch:
            patch.setattr(store.db.connection, "commit", lost_response)
            with pytest.raises(StorageFailure, match="outcome is unknown"):
                with store.db:
                    store.db.executemany("INSERT INTO settings VALUES (:p0,:p1)",
                                         [(f"new-{index}", str(index)) for index in range(count)])
        assert calls == ["committed"]
        with pytest.raises(StorageFailure, match="lost"):
            store.get_setting("new-0", None)
    finally:
        store.close()
    reopened = Store(state / "state.sqlite3")
    try:
        for index in range(count):
            assert reopened.get_setting(f"new-{index}", None) == index
            assert reopened.get_setting(f"control-{index}", None) == {"value": index}
    finally:
        reopened.close()
