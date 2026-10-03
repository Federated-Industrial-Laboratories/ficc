# SPDX-License-Identifier: Apache-2.0
"""Build distinct active identities and check isolation after rejected operations."""


def admit(issuer, provider, count):
    rows = [provider.complete(*issuer.code(index)) for index in range(count)]
    assert len({row["handle"] for row in rows}) == count
    assert [row["subject"] for row in rows] == [f"person-{index}" for index in range(count)]
    return rows


def assert_active(provider, rows):
    if not rows:
        return
    results = provider.renew([row["handle"] for row in rows])
    assert [(row["handle"], row["subject"], row["valid"]) for row in results] == [
        (row["handle"], row["subject"], True) for row in rows]


def assert_last_denied(provider, rows, results, session):
    assert [row["handle"] for row in results] == [row["handle"] for row in rows]
    assert [(row["subject"], row["valid"]) for row in results[:-1]] == [
        (row["subject"], True) for row in rows[:-1]]
    assert results[-1] == {"handle": rows[-1]["handle"], "valid": False}
    assert rows[-1]["handle"] not in provider._sessions
    assert not session.access and not session.refresh and not session.nonce
    assert_active(provider, rows[:-1])
