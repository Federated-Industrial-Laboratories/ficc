# SPDX-License-Identifier: Apache-2.0
"""Reject stale node channels and retain uncertain delivery without replay."""

import asyncio
import secrets
from types import SimpleNamespace

import pytest

from ficc.errors import Failure
from ficc.execution.protocol import Snapshot
from ficc.execution.wire import FailureReply
from ficc.workloads.channel import Channel, Exchange


def channel_fixture(count):
    sessions, nodes, revoked = {}, {}, set()
    for index in range(count):
        identity, fingerprint = f"{index + 1:032x}", f"{index + 1:064x}"
        sessions[identity] = {"id": secrets.token_hex(16), "fingerprint": fingerprint}
        nodes[fingerprint] = {"id": identity}
    def authenticate(fingerprint):
        if fingerprint not in nodes or fingerprint in revoked:
            raise Failure("node_revoked", "The contributor is revoked.", 403)
        return nodes[fingerprint], {}
    def guard(identity, session, fingerprint):
        authenticate(fingerprint)
        if sessions[identity] != {"id": session, "fingerprint": fingerprint}:
            raise Failure("node_lease_changed", "The contributor session changed.", 403)
    contributors = SimpleNamespace(sessions=sessions, guard=guard,
        records=SimpleNamespace(authenticate=authenticate), settings=SimpleNamespace(deployment_id="f" * 32))
    return Channel(SimpleNamespace(contributors=contributors)), sessions, revoked


def response(identity, command_id):
    return FailureReply(version=1, id=command_id, deployment_id="f" * 32, node_id=identity, ok=False,
                        error={"code": "synthetic_refusal", "message": "Synthetic executor response."}).model_dump()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_distinct_commands_deliver_once_and_late_revocation_does_not_affect_peer(count):
    channel, sessions, revoked = channel_fixture(max(2, count))
    requests = {}
    for identity in sessions:
        command = Snapshot(version=1, id=secrets.token_hex(16), action="snapshot", after=None)
        requests[identity] = (command, asyncio.create_task(channel.request(identity, command, lambda: None)))
    await asyncio.sleep(0)
    delivered = await asyncio.gather(*(channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"]))
                                       for session in sessions.values()))
    assert len({value["command"]["id"] for value in delivered}) == max(2, count)
    last = list(sessions)[count - 1]
    revoked.add(sessions[last]["fingerprint"])
    async def reply(identity):
        session = sessions[identity]
        return await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"],
            response=response(identity, requests[identity][0].id)))
    with pytest.raises(Failure, match="revoked"):
        await reply(last)
    healthy = [identity for identity in sessions if identity != last]
    assert all(value["command"] is None for value in await asyncio.gather(*(reply(identity) for identity in healthy)))
    for identity in healthy:
        assert (await requests[identity][1]).node_id == identity
    assert not requests[last][1].done()
    requests[last][1].cancel()
    await asyncio.gather(requests[last][1], return_exceptions=True)
    assert not channel.pending


async def test_lost_reply_is_not_redelivered_and_an_old_reply_cannot_complete_a_new_request():
    channel, sessions, _ = channel_fixture(1)
    identity, session = next(iter(sessions.items()))
    command = Snapshot(version=1, id=secrets.token_hex(16), action="snapshot", after=None)
    request = asyncio.create_task(channel.request(identity, command, lambda: None, timeout=0.1))
    await asyncio.sleep(0)
    assert (await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"]))) ["command"]["id"] == command.id
    with pytest.raises(Failure, match="Reconcile the same attempt"):
        await request
    next_command = command.model_copy(update={"id": secrets.token_hex(16)})
    pending = asyncio.create_task(channel.request(identity, next_command, lambda: None))
    await asyncio.sleep(0)
    new = await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"], response=response(identity, command.id)))
    assert new["command"]["id"] == next_command.id and not pending.done()
    repeated = await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"]))
    assert repeated["command"] is None and not pending.done()
    await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"], response=response(identity, next_command.id)))
    assert (await pending).id == next_command.id


async def test_authority_changes_before_delivery_prevent_commands_and_cross_node_results_fail():
    channel, sessions, _ = channel_fixture(2)
    identity, other = sessions
    session = sessions[identity]
    allowed = True
    def check():
        if not allowed:
            raise Failure("authority_changed", "The job authority changed.", 403)
    command = Snapshot(version=1, id=secrets.token_hex(16), action="snapshot", after=None)
    pending = asyncio.create_task(channel.request(identity, command, check))
    await asyncio.sleep(0)
    allowed = False
    with pytest.raises(Failure, match="job authority"):
        await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"]))
    with pytest.raises(Failure, match="job authority"):
        await pending
    with pytest.raises(Failure, match="another deployment or node"):
        await channel.exchange(session["fingerprint"], Exchange(version=1, session_id=session["id"], response=response(other, command.id)))
