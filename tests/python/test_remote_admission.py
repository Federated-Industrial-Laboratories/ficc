# SPDX-License-Identifier: Apache-2.0
"""Keep concurrent browser admission within its bound and release failed reservations."""

import asyncio
import threading

import pytest
from remote_fixtures import Provider, configure

from ficc.errors import Failure
from ficc.service import Service
from ficc.settings import Settings


@pytest.fixture
def admission(tmp_path):
    state = tmp_path / "state"
    configure(state)
    service = Service(Settings(state_dir=state, control=False))
    provider = Provider()
    service.remote_auth.provider = provider
    try:
        yield service.remote_auth, provider
    finally:
        service.close()


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_concurrent_browser_starts_reserve_the_last_pending_slot(admission, monkeypatch, count):
    auth, provider = admission

    async def run():
        for _ in range(127):
            await auth.begin()
        entered, release = threading.Event(), threading.Event()
        original = provider.authorization

        def authorization(*args):
            entered.set()
            assert release.wait(5)
            return original(*args)

        monkeypatch.setattr(provider, "authorization", authorization)
        tasks = [asyncio.create_task(auth.begin()) for _ in range(count)]
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            await asyncio.sleep(0)
        finally:
            release.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        accepted = [value for value in results if isinstance(value, tuple)]
        refused = [value for value in results if isinstance(value, Failure)]
        assert len(accepted) == 1 and len(refused) == count - 1
        assert all(error.status == 429 for error in refused)
        assert len(auth.pending) == len(provider.requests) == 128
        assert len({value["browser"] for value in auth.pending.values()}) == 128
        with pytest.raises(Failure) as caught:
            await auth.begin()
        assert caught.value.status == 429

    asyncio.run(run())


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_failed_authorizations_release_pending_slots(admission, monkeypatch, count):
    auth, provider = admission
    original = provider.authorization

    def invalid(*args):
        return "http://unverified.example/auth"

    def unavailable(*args):
        raise OSError("Injected authorization failure")

    async def run():
        for _ in range(count):
            for replacement in (invalid, unavailable):
                monkeypatch.setattr(provider, "authorization", replacement)
                with pytest.raises(Failure) as caught:
                    await auth.begin()
                assert caught.value.status == 503
                assert not auth.pending
        monkeypatch.setattr(provider, "authorization", original)
        await auth.begin()
        assert len(auth.pending) == 1

    asyncio.run(run())


@pytest.mark.parametrize("count", [1, pytest.param(64, marks=pytest.mark.scale)])
def test_cancelled_authorizations_release_pending_slots(admission, monkeypatch, count):
    auth, provider = admission
    entered, release = threading.Event(), threading.Event()
    original = provider.authorization

    def authorization(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(provider, "authorization", authorization)

    async def run():
        tasks = [asyncio.create_task(auth.begin()) for _ in range(count)]
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            await asyncio.sleep(0)
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert any(isinstance(value, asyncio.CancelledError) for value in results)
            assert all(isinstance(value, asyncio.CancelledError) or
                       isinstance(value, Failure) and value.status == 429 for value in results)
            assert not auth.pending
        finally:
            release.set()
        monkeypatch.setattr(provider, "authorization", original)
        await auth.begin()
        assert len(auth.pending) == 1

    asyncio.run(run())
