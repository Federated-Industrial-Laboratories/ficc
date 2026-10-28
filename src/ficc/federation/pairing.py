# SPDX-License-Identifier: Apache-2.0
"""Both cluster keys and the exact offer receipt bind finite operator-approved pairing."""
import secrets
import time

from ..errors import Failure
from ..identity_store import LOCAL_PROJECT
from . import identity
from .schema import Cluster, Offer


def peer_id(cluster, project):
    return identity.digest([cluster["key"], project])[:32]


def incoming(manager, signed, context):
    try:
        offer = Offer.model_validate(signed["payload"])
    except (ValueError, TypeError, KeyError):
        raise Failure("pairing_offer", "The pairing offer is invalid.", 422) from None
    identity.verify(signed, offer.source.key)
    own = manager.cluster()
    if (offer.destination.model_dump() != own or offer.source.network != own["network"]
            or offer.source.incarnation != own["incarnation"]
            or offer.source.principal != context["principal"]
            or offer.expires <= time.time() or offer.expires > time.time()+600):
        raise Failure("pairing_context", "The offer does not bind this cluster, caller and current pairing window.", 403)
    previous = manager.offers.find(offer.id)
    if previous:
        if previous["offer"] != signed or previous["direction"] != "incoming":
            raise Failure("pairing_replay", "This offer identifier was already bound to another request.", 409)
        return {"id": offer.id, "state": previous["state"]}
    value = {"id": offer.id, "project_id": LOCAL_PROJECT, "direction": "incoming",
             "state": "pending", "revision": 1, "offer": signed, "received_at": time.time()}
    manager.offers.save(value)
    return {"id": offer.id, "state": "pending"}


def approve(manager, offer_id, body, actor):
    actor = manager.current(actor, "federation:manage")
    value = manager.offers.get(offer_id)
    if not actor.local_owner:
        actor.require_record(value)
    offer = Offer.model_validate(value["offer"]["payload"])
    if (value["direction"] != "incoming" or value["state"] != "pending"
            or value["revision"] != body.revision or offer.expires <= time.time()):
        raise Failure("pairing_changed", "The pairing offer expired or changed; reload before approval.", 409)
    peer = {"id": peer_id(offer.source.model_dump(), actor.project_id),
            "project_id": actor.project_id, "cluster": offer.source.model_dump(),
            "state": "awaiting_confirmation", "remote_grant": None, "last_verified": time.time()}
    existing = manager.peers.find(peer["id"])
    if existing and existing["state"] not in {"removed", "suspended"}:
        raise Failure("pairing_exists", "This cluster is already paired or awaiting confirmation in the project.", 409)
    with manager.service.store.lock, manager.service.store.db:
        grant = manager.authority.create(peer, body.grant, actor)
        receipt = identity.sign(manager.key, {"version": 1, "purpose": "ficc.pair.accept",
            "offer": identity.digest(value["offer"]), "source": offer.source.model_dump(),
            "destination": manager.cluster(), "grant": grant["id"], "generation": 1,
            "spec": grant["spec"], "expires": grant["expires"]})
        peer["receipt"] = receipt
        manager.peers.save(peer)
        value.update(project_id=actor.project_id, state="accepted", revision=value["revision"]+1,
                     peer=peer["id"], receipt=receipt)
        manager.offers.save(value)
    return value


def status(manager, offer_id, caller, context):
    value = manager.offers.get(offer_id)
    offer = Offer.model_validate(value["offer"]["payload"])
    if (value["direction"] != "incoming" or offer.source.key != caller
            or offer.source.principal != context["principal"]):
        raise Failure("pairing_context", "This caller does not own the pairing offer.", 403)
    return {"id": offer_id, "state": value["state"], "receipt": value.get("receipt")}


def confirm(manager, offer_id, receipt_digest, caller, context):
    value = manager.offers.get(offer_id)
    current = status(manager, offer_id, caller, context)
    if (current["state"] not in {"accepted", "paired"}
            or identity.digest(current["receipt"]) != receipt_digest):
        raise Failure("pairing_receipt", "Confirm the exact operator-approved pairing receipt.", 403)
    peer = manager.peers.get(value["peer"])
    if peer["state"] not in {"awaiting_confirmation", "paired"} or peer["receipt"] != current["receipt"]:
        raise Failure("pairing_removed", "This peer was removed or suspended.", 403)
    peer.update(state="paired", last_verified=time.time())
    value.update(state="paired")
    with manager.service.store.lock, manager.service.store.db:
        manager.peers.save(peer)
        manager.offers.save(value)
    return {"state": "paired", "receipt": receipt_digest}


async def start(manager, target, requested, actor):
    actor = manager.current(actor, "federation:manage")
    channel, destination, challenge = await manager.client.open(target)
    try:
        offer = Offer(version=1, purpose="ficc.pair", id=secrets.token_hex(16), nonce=secrets.token_hex(32),
            source=Cluster.model_validate(manager.cluster()), destination=Cluster.model_validate(destination),
            expires=int(time.time())+600, requested=requested)
        signed = identity.sign(manager.key, offer.model_dump())
        value = {"id": offer.id, "project_id": actor.project_id, "direction": "outgoing",
                 "state": "pending", "revision": 1, "offer": signed, "created_at": time.time()}
        manager.offers.save(value)
        await manager.client.submit(channel, destination, challenge, "pair.offer", {"offer": signed})
        return value
    finally:
        await channel.close()


async def finish(manager, offer_id, actor):
    actor = manager.current(actor, "federation:manage")
    value = manager.offers.get(offer_id)
    actor.require_record(value)
    offer = Offer.model_validate(value["offer"]["payload"])
    if value["direction"] != "outgoing" or value["state"] not in {"pending", "confirming", "paired"}:
        raise Failure("pairing_changed", "The outgoing pairing offer is unavailable.", 409)
    destination = offer.destination.model_dump()
    result = await manager.client.call_cluster(destination, "pair.status", {"id": offer_id})
    if result["state"] not in {"accepted", "paired"}:
        return {"id": offer_id, "state": result["state"]}
    receipt = result["receipt"]
    accepted = identity.verify(receipt, destination["key"])
    if (accepted.get("version") != 1 or accepted.get("purpose") != "ficc.pair.accept"
            or accepted.get("offer") != identity.digest(value["offer"])
            or accepted.get("source") != offer.source.model_dump()
            or accepted.get("destination") != destination or accepted.get("expires", 0) <= time.time()):
        raise Failure("pairing_receipt", "The remote acceptance does not bind this exact pairing offer.", 403)
    peer = {"id": peer_id(destination, actor.project_id), "project_id": actor.project_id,
            "cluster": destination, "state": "confirming", "receipt": receipt,
            "remote_grant": {"id": accepted["grant"], "generation": accepted["generation"],
                             "spec": accepted["spec"], "expires": accepted["expires"]},
            "last_verified": time.time()}
    previous = manager.peers.find(peer["id"])
    if previous and previous["state"] == "removed" and previous["receipt"] == receipt:
        raise Failure("pairing_removed", "A removed peer needs a new pairing offer.", 409)
    if previous and previous["state"] not in {"removed", "suspended"} and previous["receipt"] != receipt:
        raise Failure("pairing_changed", "A different pairing receipt is already active for this peer.", 409)
    manager.peers.save(peer)
    value.update(state="confirming", peer=peer["id"], receipt=receipt)
    manager.offers.save(value)
    await manager.client.call_cluster(destination, "pair.confirm", {"id": offer_id, "receipt": identity.digest(receipt)})
    actor = manager.current(actor, "federation:manage")
    current = manager.peers.get(peer["id"])
    if current["state"] not in {"confirming", "paired"} or current["receipt"] != receipt:
        raise Failure("pairing_changed", "The peer relationship changed during confirmation.", 409)
    peer.update(state="paired", last_verified=time.time())
    value["state"] = "paired"
    manager.peers.save(peer)
    manager.offers.save(value)
    return peer
