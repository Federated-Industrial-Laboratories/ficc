# SPDX-License-Identifier: Apache-2.0
"""Qualify approved contributors through real HTTPS and mutual TLS gateways."""

import asyncio
import time

import pytest
from contributor_tls.lab import laboratory, poll, retain_material, running


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_real_enrollment_persistent_polling_rotation_and_revocation(count):
    from ficc import contributor_client

    with laboratory() as lab:
        states = await lab.cohort(count)
        async with running(states, "persistent"):
            reports = await lab.connected(states, transport="persistent")
            assert all(row["execution_available"] is False for row in reports)
            listing = lab.listing()
            assert all(listing[state.load()["node_id"]]["connected"] for state in states)
        for state in states:
            result = await contributor_client.run(state, "polling", once=True)
            assert result["transport"] == "polling" and result["execution_available"] is False
        target = states[-1]
        before = target.load()
        old = before["current"].copy()
        retained = retain_material(target)
        await contributor_client.rotate(target, before)
        after = target.load()
        assert after["current"]["public_key"] != old["public_key"]
        assert after["current"]["fingerprint"] != old["fingerprint"]
        assert not target.file(old["key_file"]).exists()
        assert not target.file(old["certificate_file"]).exists()
        assert (await poll(target, material=retained)).status_code == 403
        async with running(states, "persistent"):
            await lab.connected(states, transport="persistent")
            started = time.monotonic()
            lab.disable(target)
            while lab.report(target).get("status") == "connected" and time.monotonic() - started < 4:
                await asyncio.sleep(0.05)
            assert lab.report(target)["status"] == "disconnected"
            response = await poll(target)
            assert response.status_code == 403
            if count > 1:
                assert lab.report(states[0])["status"] == "connected"
                assert lab.listing()[states[0].load()["node_id"]]["connected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_automatic_rotation_preserves_identity_and_rejects_previous_key(count):
    with laboratory(certificate_seconds=60) as lab:
        states = await lab.cohort(count)
        before = [state.load() for state in states]
        retained = retain_material(states[-1])
        async with running(states, "persistent"):
            await lab.connected(states, transport="persistent")
            end = time.monotonic() + 60
            while time.monotonic() < end:
                current = [state.load() for state in states]
                if all(new["current"]["fingerprint"] != old["current"]["fingerprint"]
                       for old, new in zip(before, current, strict=True)):
                    break
                await asyncio.sleep(0.2)
            else:
                raise AssertionError("Automatic rotation did not complete for every node.")
            await lab.connected(states, transport="persistent")
            for old, new in zip(before, current, strict=True):
                assert old["node_id"] == new["node_id"]
                assert old["current"]["public_key"] != new["current"]["public_key"]
                assert old["current"]["fingerprint"] != new["current"]["fingerprint"]
            assert (await poll(states[-1], material=retained)).status_code == 403
            listing = lab.listing()
            assert all(listing[state.load()["node_id"]]["connected"] for state in states)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
async def test_polling_fallback_gateway_loss_and_lease_recovery(count):
    with laboratory() as lab:
        states = await lab.cohort(count)
        lab.gateway.close()
        lab.gateway.start(polling_only=True)
        async with running(states, "auto"):
            await lab.connected(states, transport="polling", timeout=20)
            listing = lab.listing()
            assert all(listing[state.load()["node_id"]]["connected"] for state in states)
            lab.gateway.close()
            await asyncio.sleep(6)
            listing = lab.listing()
            assert all(not listing[state.load()["node_id"]]["connected"] for state in states)
            assert all(lab.report(state)["execution_available"] is False for state in states)
            assert all(lab.report(state)["status"] == "disconnected" for state in states)
            lab.gateway.start()
            await lab.connected(states, timeout=20)
            listing = lab.listing()
            assert all(listing[state.load()["node_id"]]["connected"] for state in states)
