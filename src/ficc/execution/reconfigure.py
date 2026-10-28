# SPDX-License-Identifier: Apache-2.0
"""Apply an administrator's new installed offer after every retained attempt is released."""
import os
from pathlib import Path

from .ledger import Ledger
from .offer import validate_offer
from .process import properties


def reconfigure(settings, revision):
    if os.geteuid() != 0:
        raise ValueError("Offer reconfiguration requires the machine administrator.")
    current = properties(settings.service, ("ActiveState", "MainPID"))
    if current.get("ActiveState") not in {"inactive", "failed"} or current.get("MainPID") != "0":
        raise ValueError("Stop the installed supervisor before applying its new offer.")
    ledger = Ledger(Path(settings.state), settings.installation_id)
    try:
        with ledger.lock, ledger.db:
            if any(item["state"] != "released" for item in ledger.all()):
                raise ValueError("Release every retained attempt before changing the installed runtime offer.")
            value = settings.initial_offer.model_copy(update={"revision": revision + 1})
            validate_offer(value, settings.ceiling)
            ledger.save_offer(value, revision)
            return {"installation_id": settings.installation_id, "offer": value.model_dump()}
    finally:
        ledger.close()
