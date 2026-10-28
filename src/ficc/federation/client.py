# SPDX-License-Identifier: Apache-2.0
"""Each remote request proves the cluster key against a fresh stream-bound challenge."""
import asyncio
import secrets
import time

from ..errors import Failure
from ..inference.stream import Stream
from . import identity
from .schema import PROTOCOL, Cluster, Request


class Client:
    def __init__(self, manager):
        self.manager = manager

    async def open(self, target, expected=None):
        channel = await self.manager.transport().connect(target)
        try:
            async with asyncio.timeout(30):
                signed = await channel.json()
            cluster = Cluster.model_validate(signed["payload"]["cluster"]).model_dump()
            hello = identity.verify(signed, cluster["key"])
            peer = channel.peer
            if (hello.get("version") != 1 or hello.get("purpose") != "ficc.challenge"
                    or cluster["service"] != target or peer.get("service") != target
                    or peer.get("protocol") != PROTOCOL or cluster["network"] != peer.get("network")
                    or cluster["incarnation"] != peer.get("incarnation")
                    or hello.get("session") != peer.get("session")
                    or hello.get("generation") != peer.get("generation")
                    or hello.get("expires", 0) <= time.time()
                    or (expected is not None and cluster != expected)):
                raise Failure("federation_identity", "The remote cluster differs from its verified HyperNet service or pairing.", 403)
            return channel, cluster, hello["challenge"]
        except BaseException:
            await channel.close()
            raise

    async def submit(self, channel, cluster, challenge, operation, body, grant=None, request_id=None):
        request = Request(version=1, purpose="ficc.request", id=request_id or secrets.token_hex(16),
            challenge=challenge, source=self.manager.cluster()["key"], destination=cluster["key"],
            operation=operation, body=body, grant=grant["id"] if grant else None,
            generation=grant["generation"] if grant else 1)
        if len(identity.encode(request.model_dump())) > 512*1024:
            raise Failure("federation_limit", "The federation request exceeds 512 KiB.", 413)
        await channel.send_json(identity.sign(self.manager.key, request.model_dump()))
        response = await channel.json()
        if response.get("version") != 1 or response.get("id") != request.id or not isinstance(response.get("ok"), bool):
            raise Failure("federation_protocol", "The response does not identify this request.", 502)
        if not response["ok"]:
            error = response.get("error", {})
            status = error.get("status", 502)
            status = status if type(status) is int and 400 <= status <= 599 else 502
            raise Failure(str(error.get("code", "federation_refused")),
                str(error.get("message", "The remote cluster refused the operation.")),
                status)
        result = response.get("result")
        if not isinstance(result, dict):
            raise Failure("federation_protocol", "The peer returned an invalid operation result.", 502)
        return result

    async def call_cluster(self, cluster, operation, body):
        channel, destination, challenge = await self.open(cluster["service"], cluster)
        try:
            async with asyncio.timeout(60):
                return await self.submit(channel, destination, challenge, operation, body)
        finally:
            await channel.close()

    def peer(self, identity, actor):
        actor = self.manager.current(actor, "federation:invoke")
        peer = self.manager.peers.get(identity)
        actor.require_record(peer)
        grant = peer.get("remote_grant")
        if peer["state"] != "paired" or not grant or grant["expires"] <= time.time():
            raise Failure("federation_unavailable", "This peer has no current accepted remote grant.", 409)
        return peer, grant

    async def request(self, peer_id, operation, body, actor, request_id=None):
        peer, grant = self.peer(peer_id, actor)
        channel, destination, challenge = await self.open(peer["cluster"]["service"], peer["cluster"])
        owned = self.manager.outgoing.setdefault(peer_id, set())
        owned.add(channel)
        try:
            self.peer(peer_id, actor)
            async with asyncio.timeout(120):
                result = await self.submit(channel, destination, challenge, operation, body, grant, request_id)
            current, _ = self.peer(peer_id, actor)
            if current["cluster"] != peer["cluster"] or current["receipt"] != peer["receipt"]:
                raise Failure("pairing_changed", "The peer relationship changed during the request.", 409)
            current["last_verified"] = time.time()
            self.manager.peers.save(current)
            if result.get("stream") is not True:
                await channel.close()
                owned.discard(channel)
                return result, None
            maximum = grant["spec"]["response_bytes"] if operation == "inference.invoke" else 256*1024*1024
            async def cleanup():
                owned.discard(channel)
                await channel.close()
            async def chunks():
                total = 0
                async with asyncio.timeout(3600):
                    while True:
                        self.peer(peer_id, actor)
                        data = await channel.receive()
                        if not data:
                            break
                        total += len(data)
                        if total > maximum:
                            raise Failure("federation_response_limit", "The remote response exceeded its finite allowance.", 502)
                        yield data
            return result, Stream(chunks(), cleanup)
        except BaseException:
            owned.discard(channel)
            await channel.close()
            raise
