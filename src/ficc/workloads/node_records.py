# SPDX-License-Identifier: Apache-2.0
"""Retain observed local offers without treating saved capacity as live authority."""

import time

from ..errors import Failure
from ..execution.wire import Snapshot
from ..schema import Model
from .schema import Timestamp


class Observation(Model):
    snapshot: Snapshot
    observed_at: Timestamp


class Nodes:
    def __init__(self, store):
        self.store = store

    def all(self):
        with self.store.lock:
            rows = self.store.db.execute("SELECT value FROM workload_nodes ORDER BY node_id").fetchall()
        return [Observation.model_validate_json(row[0]) for row in rows]

    def save(self, snapshot):
        with self.store.lock, self.store.db:
            identity = snapshot.node_id
            row = self.store.db.execute("SELECT value FROM workload_nodes WHERE node_id=:p0", (identity,)).fetchone()
            if row:
                previous = Observation.model_validate_json(row[0]).snapshot
                replaced = previous.installation_id != snapshot.installation_id or (
                    previous.ledger_id is not None and previous.ledger_id != snapshot.ledger_id)
                if replaced:
                    from .records import Records
                    if any(item.state != "released" for item in Records(self.store).attempts(identity)):
                        raise Failure("executor_replaced", "Resolve retained attempts before accepting a replacement executor ledger.", 409)
                if previous.installation_id == snapshot.installation_id:
                    if (previous.offer.revision > snapshot.offer.revision or
                            previous.offer.revision == snapshot.offer.revision and previous.offer != snapshot.offer):
                        raise Failure("offer_changed", "The local offer revision is stale or inconsistent.", 409)
            value = Observation(snapshot=snapshot.model_copy(update={"attempts": [], "next": None}), observed_at=time.time())
            self.store.db.execute("INSERT INTO workload_nodes VALUES (:p0,:p1) "
                                 "ON CONFLICT(node_id) DO UPDATE SET value=excluded.value", (identity, value.model_dump_json()))
            return value


def validate_records(db, nodes):
    for identity, raw in db.execute("SELECT node_id,value FROM workload_nodes"):
        value = Observation.model_validate_json(raw)
        if (identity not in nodes or value.snapshot.node_id != identity
                or value.snapshot.attempts or value.snapshot.next is not None):
            raise ValueError("A saved execution offer has an invalid node binding.")
