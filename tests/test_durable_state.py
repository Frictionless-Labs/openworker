"""M09 durable state corpus (OW-REL-001).

The invariant: **one malformed state file must not brick startup, and recovery must not
destroy the evidence.** Both halves matter — catching the error and starting empty would
pass the first and fail the second, and it is the second that tells an operator afterwards
whether they had a disk-full crash or something worth investigating.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from coworker.inbox import InboxStore
from coworker.inbox_routing import InboxRouting
from coworker.jsonstate import (
    RecoveryEvent,
    read_json_safe,
    set_recovery_sink,
    write_json_atomic,
)
from coworker.mentions import MentionSessionStore
from coworker.overrides import RiskOverrideStore
from coworker.unattended import UnattendedRegistry
from coworker.unrouted import UnroutedStore


@pytest.fixture
def recoveries():
    seen: list[RecoveryEvent] = []
    set_recovery_sink(seen.append)
    yield seen
    set_recovery_sink(None)


# Every byte sequence a half-finished or hostile write can leave behind.
CORRUPTIONS = [
    ("truncated object", '{"items": [{"id": "a"'),
    ("truncated array", '{"items": ['),
    ("empty file", ""),
    ("whitespace only", "   \n  "),
    ("nul bytes", "\x00\x00\x00\x00"),
    ("not json at all", "<html>500 Internal Server Error</html>"),
    ("json fragment", '"items"'),
    ("trailing garbage", '{"items": []}}}}'),
    ("bare newline", "\n"),
]


# -- 1. Startup survives every corruption ---------------------------------------

STORES = [
    ("inbox", lambda p: InboxStore(p)),
    ("inbox_routing", lambda p: InboxRouting(p)),
    ("mentions", lambda p: MentionSessionStore(p)),
    ("unrouted", lambda p: UnroutedStore(p)),
    ("unattended", lambda p: UnattendedRegistry(p)),
    ("risk_overrides", lambda p: RiskOverrideStore(p)),
]


@pytest.mark.parametrize("store_name,factory", STORES, ids=[s[0] for s in STORES])
@pytest.mark.parametrize("label,payload", CORRUPTIONS, ids=[c[0] for c in CORRUPTIONS])
def test_a_corrupt_store_does_not_prevent_construction(
    tmp_path, recoveries, store_name, factory, label, payload
):
    """Every one of these constructors runs during server boot."""
    path = tmp_path / f"{store_name}.json"
    path.write_text(payload, encoding="utf-8")
    factory(path)  # must not raise
    assert list(tmp_path.glob(f"{store_name}.json.corrupt-*")), (
        f"{store_name}/{label}: the bad file must be preserved for diagnosis"
    )


@pytest.mark.parametrize("store_name,factory", STORES, ids=[s[0] for s in STORES])
def test_a_missing_store_is_a_normal_first_run(tmp_path, store_name, factory):
    """Absent is not corrupt: nothing is quarantined and nothing is logged."""
    factory(tmp_path / f"{store_name}.json")
    assert not list(tmp_path.glob("*.corrupt-*"))


def test_one_corrupt_store_does_not_take_the_others_down(tmp_path, recoveries):
    (tmp_path / "inbox.json").write_text('{"items": [', encoding="utf-8")
    InboxRouting(tmp_path / "routing.json").set_binding("ops", channel="slack", target="#o")

    inbox = InboxStore(tmp_path / "inbox.json")
    routing = InboxRouting(tmp_path / "routing.json")

    assert inbox.pending() == []
    assert routing.binding_for("ops").target == "#o", "the healthy store is untouched"


def test_a_record_from_a_different_schema_loses_that_record_not_the_file(tmp_path):
    """Schema drift is not corruption of the whole store."""
    good = {"id": "a", "session_id": "s1", "kind": "approval", "title": "t"}
    path = tmp_path / "inbox.json"
    path.write_text(
        json.dumps({"items": [good, {"id": "b", "from_the_future": True}]}),
        encoding="utf-8",
    )
    store = InboxStore(path)
    assert [i.id for i in store.list()] == ["a"]
    assert not list(tmp_path.glob("*.corrupt-*")), "a readable file is not quarantined"


# -- 2. Recovery preserves evidence without leaking content ---------------------


def test_the_quarantined_file_keeps_the_original_bytes(tmp_path, recoveries):
    path = tmp_path / "inbox.json"
    path.write_text('{"items": [{"secret": "do-not-lose-me"', encoding="utf-8")
    InboxStore(path)
    quarantined = next(tmp_path.glob("inbox.json.corrupt-*"))
    assert "do-not-lose-me" in quarantined.read_text()


def test_the_recovery_event_names_the_store_and_reason_but_no_content(tmp_path, recoveries):
    path = tmp_path / "inbox.json"
    path.write_text('{"items": [{"body": "confidential minutes"', encoding="utf-8")
    InboxStore(path)

    assert len(recoveries) == 1
    event = recoveries[0]
    assert event.store == "inbox"
    assert "invalid JSON" in event.reason
    assert event.quarantine_ref
    blob = f"{event.store} {event.reason} {event.quarantine_ref}"
    assert "confidential minutes" not in blob


def test_recovery_is_repeatable(tmp_path, recoveries):
    """A store corrupted twice quarantines twice, never overwriting the first evidence."""
    path = tmp_path / "inbox.json"
    for _ in range(2):
        path.write_text("{", encoding="utf-8")
        InboxStore(path)
    assert len(list(tmp_path.glob("inbox.json.corrupt-*"))) >= 1
    assert len(recoveries) == 2


def test_a_store_stays_usable_after_recovery(tmp_path, recoveries):
    path = tmp_path / "inbox.json"
    path.write_text("{", encoding="utf-8")
    store = InboxStore(path)
    item = store.add_approval("s1", "Run it?")
    assert InboxStore(path).get(item.id).title == "Run it?"


# -- 3. Writes are atomic -------------------------------------------------------


def test_write_leaves_no_partial_file_when_serialization_fails(tmp_path):
    """Serialization happens before the temp file is opened, so an unencodable value
    raises without having touched the disk."""
    path = tmp_path / "s.json"
    write_json_atomic(path, {"a": 1})

    class _Boom:
        def __repr__(self):
            raise ValueError("nope")

    with pytest.raises(ValueError):
        write_json_atomic(path, {"bad": _Boom()})
    assert json.loads(path.read_text()) == {"a": 1}, "the previous file is intact"
    assert not list(tmp_path.glob("*.tmp")), "no temp file left behind"


def test_the_temp_file_lives_in_the_target_directory(tmp_path, monkeypatch):
    """A rename across filesystems is not atomic; the temp file must be a sibling."""
    seen = {}
    import tempfile as _t

    real = _t.mkstemp

    def spy(*args, **kwargs):
        seen["dir"] = kwargs.get("dir")
        return real(*args, **kwargs)

    monkeypatch.setattr("coworker.jsonstate.tempfile.mkstemp", spy)
    target = tmp_path / "nested" / "s.json"
    write_json_atomic(target, {"a": 1})
    assert seen["dir"] == str(target.parent)


def test_an_interrupted_write_is_never_observed(tmp_path):
    """Simulate the crash window: a temp file exists but the replace never happened. The
    live file must still be the previous COMPLETE version, not a half one."""
    path = tmp_path / "s.json"
    write_json_atomic(path, {"generation": 1})
    (tmp_path / "s.json.abcd.tmp").write_text('{"generation": 2')  # died mid-write
    assert read_json_safe(path, default={}) == {"generation": 1}


def test_concurrent_writers_never_produce_a_partial_read(tmp_path):
    path = tmp_path / "s.json"
    write_json_atomic(path, {"n": 0})
    errors: list[Exception] = []

    def writer(n):
        try:
            for _ in range(40):
                write_json_atomic(path, {"n": n, "payload": "x" * 2000})
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    def reader():
        try:
            for _ in range(120):
                value = read_json_safe(path, default=None)
                assert value is None or "n" in value
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
    threads += [threading.Thread(target=reader) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert not list(tmp_path.glob("*.corrupt-*")), "no reader ever saw a half file"


def test_round_trip_through_every_migrated_store(tmp_path):
    inbox = InboxStore(tmp_path / "inbox.json")
    item = inbox.add_approval("s1", "t")
    assert InboxStore(tmp_path / "inbox.json").get(item.id) is not None

    routing = InboxRouting(tmp_path / "routing.json")
    routing.set_binding("ops", channel="telegram", target="42")
    assert InboxRouting(tmp_path / "routing.json").binding_for("ops").target == "42"

    unattended = UnattendedRegistry(tmp_path / "unattended.json")
    unattended.set("s1", True)
    assert UnattendedRegistry(tmp_path / "unattended.json").is_unattended("s1") is True

    unrouted = UnroutedStore(tmp_path / "unrouted.json")
    unrouted.record("slack", "u1", "hello", "no session")
    assert len(UnroutedStore(tmp_path / "unrouted.json").list()) == 1


def test_the_written_file_is_valid_json_on_disk(tmp_path):
    path = tmp_path / "s.json"
    write_json_atomic(path, {"a": [1, 2, {"b": None}]})
    assert json.loads(path.read_text()) == {"a": [1, 2, {"b": None}]}
