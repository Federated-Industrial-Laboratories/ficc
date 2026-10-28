# SPDX-License-Identifier: Apache-2.0
"""Own local federation configuration and bounded authenticated request lifetimes."""
import asyncio
import secrets
import time

from ..errors import Failure
from . import identity, operations, pairing
from .authority import Authority
from .client import Client
from .records import Records
from .schema import PROTOCOL, Cluster, Request
from .transport import HyperNet


class Federation:
    def __init__(self, service):
        self.service = service
        self.key = identity.key(service.settings.state_dir / "federation")
        self.peers = Records(service.store, "federation_peers")
        self.offers = Records(service.store, "federation_offers")
        self.grants = Records(service.store, "federation_grants")
        self.operations = Records(service.store, "federation_operations")
        self.authority = Authority(self)
        self.client = Client(self)
        self.connections: set[asyncio.Task] = set()
        self.outgoing: dict[str, set] = {}
        self.transfers: dict[str, dict] = {}
        self.last_error = None
        self._transport = None

    def current(self, actor, scope):
        current = self.service.auth.current(actor.id)
        current.require(scope)
        if current.node_ids is not None or current.root_ids is not None:
            raise Failure("denied", "Federation requires a project credential without machine restrictions.", 403)
        return current

    def cluster(self):
        config = self.service.store.get_setting("federation.configuration", None)
        if config is None:
            raise Failure("federation_unconfigured", "Configure the dedicated HyperNet companion before pairing clusters.", 409)
        return config["cluster"]

    def transport(self):
        config = self.service.store.get_setting("federation.configuration", None)
        if config is None:
            raise Failure("federation_unconfigured", "Configure the dedicated HyperNet companion before pairing clusters.", 409)
        if self._transport is None:
            self._transport = HyperNet(config["agent_directory"])
        return self._transport

    async def configure(self, body, actor):
        actor = self.current(actor, "federation:manage")
        if not actor.local_owner:
            raise Failure("denied", "The local owner configures the host's HyperNet companion.", 403)
        transport = HyperNet(body.agent_directory)
        status = await transport.status()
        binding = status.get("binding") or {}
        if not status.get("incoming") or binding.get("protocol") != PROTOCOL:
            raise Failure("hypernet_binding", "Use a dedicated companion with an accepted ficc.federation/1 service binding.", 409)
        cluster = Cluster(key=self.key.public_key().public_bytes_raw().hex(), label=body.label,
            network=status["network"], incarnation=status["incarnation"],
            principal=status["principal"], service=binding["service"]).model_dump()
        previous = self.service.store.get_setting("federation.configuration", None)
        if previous and previous["cluster"] != cluster and any(p["state"] not in {"removed", "suspended"} for p in self.peers.all()):
            raise Failure("federation_identity_changed", "Remove current pairings before changing the cluster or transport identity.", 409)
        self.service.store.set_setting("federation.configuration", {"agent_directory": body.agent_directory, "cluster": cluster})
        self._transport = transport
        self.service.store.audit("federation.configure", cluster["service"], actor=actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)
        return {"cluster": cluster, "transport": status}

    async def status(self, actor):
        self.current(actor, "federation:read")
        config = self.service.store.get_setting("federation.configuration", None)
        transport = None
        if config:
            try:
                transport = await self.transport().status()
                self.last_error = None
            except Failure as exc:
                self.last_error = {"code": exc.code, "message": str(exc)}
        return {"configured": config is not None, "cluster": config["cluster"] if config else None,
                "agent_directory": config["agent_directory"] if config and actor.local_owner else None,
                "transport": transport, "error": self.last_error, "connections": len(self.connections)}

    async def remove(self, identity, actor):
        actor = self.current(actor, "federation:manage")
        peer = self.peers.get(identity)
        actor.require_record(peer)
        for grant in self.grants.all(actor.project_id):
            if grant["peer"] == identity and grant["state"] == "active":
                await self.authority.revoke(grant["id"], actor)
        peer.update(state="removed", remote_grant=None)
        self.peers.save(peer)
        await asyncio.gather(*(channel.close() for channel in list(self.outgoing.get(identity, ()))), return_exceptions=True)
        self.service.store.audit("federation.remove", identity, actor=actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)
        return peer

    async def retire(self, identity, actor):
        actor = self.current(actor, "federation:manage")
        grant = self.grants.get(identity)
        actor.require_record(grant)
        if grant["state"] not in {"revoked", "suspended"}:
            raise Failure("federation_active", "Revoke the grant before retiring its receipts.", 409)
        # Revocation is permanent. Removing these receipts cannot make the old
        # grant admissible or turn an uncertain request into an eligible replay.
        await self.authority.revoke(identity, actor)
        with self.service.store.lock, self.service.store.db:
            for record in self.operations.all(actor.project_id):
                if record["grant"] == identity:
                    self.operations.remove(record["id"])
            self.grants.remove(identity)
        self.service.store.audit("federation.retire", identity, actor=actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)
        return {"retired": True}

    async def forget(self, identity, actor):
        actor = self.current(actor, "federation:manage")
        peer = self.peers.get(identity)
        actor.require_record(peer)
        if peer["state"] not in {"removed", "suspended"}:
            raise Failure("federation_active", "Remove the peer before forgetting its receipts.", 409)
        for grant in self.grants.all(actor.project_id):
            if grant["peer"] == identity:
                await self.authority.revoke(grant["id"], actor)
                await self.retire(grant["id"], actor)
        with self.service.store.lock, self.service.store.db:
            for offer in self.offers.all(actor.project_id):
                if offer.get("peer") == identity:
                    self.offers.remove(offer["id"])
            self.peers.remove(identity)
        self.outgoing.pop(identity, None)
        self.service.store.audit("federation.forget", identity, actor=actor.id,
                                 subject_id=actor.subject_id, project_id=actor.project_id)
        return {"forgotten": True}

    async def serve(self, channel):
        request = None
        admitted = False
        sent = False
        try:
            cluster = self.cluster()
            context = channel.peer
            if (context.get("service") != cluster["service"] or context.get("protocol") != PROTOCOL
                    or context.get("network") != cluster["network"]
                    or context.get("incarnation") != cluster["incarnation"]):
                raise Failure("federation_transport", "The incoming verified HyperNet binding differs from this cluster.", 403)
            challenge = secrets.token_hex(32)
            await channel.send_json(identity.sign(self.key, {"version": 1, "purpose": "ficc.challenge",
                "cluster": cluster, "challenge": challenge, "session": context["session"],
                "generation": context["generation"], "expires": int(time.time())+30}))
            async with asyncio.timeout(30):
                signed = await channel.json()
            request = Request.model_validate(signed["payload"])
            identity.verify(signed, request.source)
            if request.destination != cluster["key"] or request.challenge != challenge:
                raise Failure("federation_challenge", "The request belongs to another cluster or connection.", 403)
            if request.operation == "peer.grants":
                operations.exact(request.body, ["receipt"])
                peers = [p for p in self.peers.all() if p["state"] == "paired"
                         and p["cluster"]["key"] == request.source
                         and p["cluster"]["principal"] == context["principal"]
                         and identity.digest(p["receipt"]) == request.body["receipt"]]
                if len(peers) != 1:
                    raise Failure("pairing_inactive", "The exact paired relationship is unavailable.", 403)
                grants = [{k: grant[k] for k in ("id", "generation", "spec", "expires")}
                          for grant in self.grants.all(peers[0]["project_id"])
                          if grant["peer"] == peers[0]["id"] and grant["state"] == "active" and grant["expires"] > time.time()]
                await channel.send_json({"version": 1, "id": request.id, "ok": True, "result": {"grants": grants}})
                return
            if request.operation.startswith("pair."):
                if request.grant is not None:
                    raise Failure("pairing_context", "Pairing requests cannot use a resource grant.", 422)
                body = request.body
                if request.operation == "pair.offer":
                    operations.exact(body, ["offer"])
                    if body["offer"]["payload"]["source"]["key"] != request.source:
                        raise Failure("pairing_context", "The offer and request use different cluster keys.", 403)
                    result = pairing.incoming(self, body["offer"], context)
                elif request.operation == "pair.status":
                    operations.exact(body, ["id"])
                    result = pairing.status(self, body["id"], request.source, context)
                elif request.operation == "pair.confirm":
                    operations.exact(body, ["id", "receipt"])
                    result = pairing.confirm(self, body["id"], body["receipt"], request.source, context)
                else:
                    raise Failure("federation_operation", "The pairing operation is unsupported.", 422)
                await channel.send_json({"version": 1, "id": request.id, "ok": True, "result": result})
                return
            if request.grant is None:
                raise Failure("federation_grant", "This operation requires an accepted FICC peer grant.", 403)
            grant = self.grants.get(request.grant)
            peer = self.peers.get(grant["peer"])
            if peer["cluster"]["key"] != request.source or peer["cluster"]["principal"] != context["principal"]:
                raise Failure("federation_identity", "The FICC key and HyperNet principal do not match this peer grant.", 403)
            self.authority.admit(request, peer)
            admitted = True
            async def execute():
                nonlocal sent
                result, stream = await operations.dispatch(self, request, peer)
                try:
                    self.authority.check(request.grant, peer, request.generation)
                    await channel.send_json({"version": 1, "id": request.id, "ok": True, "result": result})
                    sent = True
                    if stream is not None:
                        async for data in stream:
                            self.authority.check(request.grant, peer, request.generation)
                            for start in range(0, len(data), 1024*1024):
                                await channel.send(data[start:start+1024*1024])
                        await channel.send(b"")
                finally:
                    if stream is not None:
                        await stream.aclose()
            # A closed caller cancels a live engine iterator even while it is
            # waiting for its first response; no request is replayed elsewhere.
            operation = asyncio.create_task(execute())
            disconnected = asyncio.create_task(channel.reader.read(1))
            try:
                async with asyncio.timeout(3600):
                    done, _ = await asyncio.wait((operation, disconnected), return_when=asyncio.FIRST_COMPLETED)
                    if operation in done:
                        await operation
                    else:
                        raise Failure("federation_cancelled", "The caller disconnected or sent an extra request.", 499)
            finally:
                operation.cancel()
                disconnected.cancel()
                await asyncio.gather(operation, disconnected, return_exceptions=True)
        except (Failure, ValueError, KeyError, TypeError, OSError, asyncio.IncompleteReadError) as exc:
            if request is not None and not sent:
                error = exc if isinstance(exc, Failure) else Failure("federation_request", "The federation request could not be processed.", 422)
                try:
                    await channel.send_json({"version": 1, "id": request.id, "ok": False,
                        "error": {"code": error.code, "message": str(error), "status": error.status}})
                except (OSError, ConnectionError):
                    pass
        finally:
            if admitted and request is not None:
                self.authority.release(request.grant)
            await channel.close()

    async def run(self):
        while True:
            if not self.service.store.get_setting("federation.configuration", None):
                await asyncio.sleep(1)
                continue
            try:
                if len(self.connections) >= 16:
                    await asyncio.sleep(0.1)
                    continue
                channel = await self.transport().accept()
                task = asyncio.create_task(self.serve(channel))
                self.connections.add(task)
                task.add_done_callback(self.connections.discard)
                self.last_error = None
            except (OSError, RuntimeError, Failure) as exc:
                if getattr(exc, "code", None) != "Timeout":
                    self.last_error = {"code": getattr(exc, "code", "hypernet_unavailable"),
                                       "message": "The HyperNet companion refused or interrupted application acceptance."}
                await asyncio.sleep(0.2)

    async def close(self):
        channels = [channel for values in self.outgoing.values() for channel in values]
        await asyncio.gather(*(channel.close() for channel in channels), return_exceptions=True)
        tasks = list(self.connections) + [item["task"] for item in self.transfers.values() if item.get("task")]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def refresh_grants(self, peer_id, actor, selected=None):
        actor = self.current(actor, "federation:manage")
        peer = self.peers.get(peer_id)
        actor.require_record(peer)
        if peer["state"] != "paired":
            raise Failure("pairing_inactive", "Complete pairing before refreshing remote grants.", 409)
        result = await self.client.call_cluster(peer["cluster"], "peer.grants", {"receipt": identity.digest(peer["receipt"])})
        actor = self.current(actor, "federation:manage")
        current = self.peers.get(peer_id)
        actor.require_record(current)
        if current["state"] != "paired" or current["receipt"] != peer["receipt"]:
            raise Failure("pairing_changed", "The peer relationship changed while refreshing its grants.", 409)
        peer = current
        if selected is not None:
            grants = [grant for grant in result["grants"] if grant["id"] == selected]
            if len(grants) != 1:
                raise Failure("federation_grant", "Select one currently published remote grant.", 403)
            peer.update(remote_grant=grants[0], last_verified=time.time())
            self.peers.save(peer)
        return result
