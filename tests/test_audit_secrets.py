"""M07 audit + secrets corpus (OW-SEC-015/016).

Two invariants:

1. **The audit trail explains authority, not content.** Every assertion below reads the
   PERSISTED SQLite row, not the value passed in — a sanitizer that runs on the way to the
   UI and not on the way to disk would pass an in-memory test and still leave the bytes on
   the disk, which is the thing that matters.
2. **A credential migration never leaves exactly one copy.** Write, verify by reading back,
   and only then retire the legacy file — by rename, never by delete.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from coworker.audit import AuditStore
from coworker.secrets import (
    FileBackend,
    KeychainBackend,
    MigrationError,
    SecretStore,
)


# -- helpers --------------------------------------------------------------------


def _row(tmp_path, result, *, tool="gmail_list", preview=None, name="audit.db"):
    store = AuditStore(tmp_path / name)
    store.append(
        {
            "tool": tool,
            "stage": "finished",
            "status": "ok",
            "approval": "allow_once",
            "call_id": "call-1",
            "resource": "",
            "arguments": {"label": "INBOX"},
            "result": result,
            "result_preview": preview if preview is not None else json.dumps(result, default=str),
        }
    )
    store.close()
    conn = sqlite3.connect(tmp_path / name)
    conn.row_factory = sqlite3.Row
    out = dict(conn.execute("SELECT * FROM audit_events").fetchone())
    conn.close()
    return out


# -- 1. Nothing sensitive survives to disk --------------------------------------

SENSITIVE = [
    ("email body", {"messages": [{"id": "m1", "body": "the wire details are 1234-5678"}]}, "wire details"),
    ("html content", {"html": "<b>internal roadmap</b>"}, "internal roadmap"),
    ("text field", {"text": "confidential minutes"}, "confidential minutes"),
    ("snippet", {"snippet": "leaked snippet text"}, "leaked snippet text"),
    ("environment output", {"env": {"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI"}}, "wJalrXUtnFEMI"),
    ("environment nested", {"result": {"environment": {"API_KEY": "supersecret"}}}, "supersecret"),
    ("token key", {"token": "xoxb-1111111111-2222"}, "xoxb-1111111111-2222"),
    ("access_token key", {"data": {"access_token": "at-abcdef123456"}}, "at-abcdef123456"),
    ("bot_token key", {"bot_token": "xoxb-bot-token-value"}, "xoxb-bot-token-value"),
    ("app_token key", {"app_token": "xapp-app-token-value"}, "xapp-app-token-value"),
    ("api_key key", {"api_key": "key-abcdef"}, "key-abcdef"),
    ("password key", {"auth": {"password": "hunter2"}}, "hunter2"),
    ("secret key", {"secret": "classified"}, "classified"),
    ("deeply nested credential", {"a": {"b": {"c": {"credential": {"token": "deep-secret"}}}}}, "deep-secret"),
    ("credential inside a list", {"items": [{"api_key": "list-secret"}]}, "list-secret"),
    ("secret literal in a plain value", {"note": "sk-ant-abcdefghijklmnopqrstuvwx"}, "sk-ant-abcdefghijkl"),
    ("secret literal in a list of strings", {"lines": ["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}, "ghp_aaaaaaaa"),
    ("private key block", {"out": "-----BEGIN RSA PRIVATE KEY-----\nMIIE"}, "BEGIN RSA PRIVATE KEY"),
]


@pytest.mark.parametrize("label,result,needle", SENSITIVE, ids=[r[0] for r in SENSITIVE])
def test_sensitive_values_do_not_reach_the_persisted_row(tmp_path, label, result, needle):
    row = _row(tmp_path, result)
    blob = json.dumps(dict(row), default=str)
    assert needle not in blob, f"{label}: leaked into the audit row"
    assert "[redacted" in row["result_preview"], f"{label}: expected a redaction marker"


def test_a_bare_secret_string_result_is_redacted(tmp_path):
    row = _row(tmp_path, "sk-ant-abcdefghijklmnopqrstuvwx")
    assert "sk-ant-abcdef" not in row["result_preview"]


def test_truncation_is_not_redaction(tmp_path):
    """A 500-char prefix of an email body is still an email body, and a short token
    survives truncation whole. Redaction must run BEFORE the flatten/truncate."""
    row = _row(tmp_path, {"body": "x" * 5000 + "SENSITIVE-TAIL"})
    assert "xxxx" not in row["result_preview"]
    assert row["result_preview"] == '{"body": "[redacted body]"}'


# -- 2. The row is still useful --------------------------------------------------


def test_the_row_still_identifies_the_action(tmp_path):
    row = _row(tmp_path, {"id": "m1", "url": "https://mail.test/m1", "body": "secret"})
    assert row["tool"] == "gmail_list"
    assert row["stage"] == "finished"
    assert row["status"] == "ok"
    assert row["approval"] == "allow_once"
    assert row["call_id"] == "call-1"
    assert row["resource"] == "https://mail.test/m1"
    assert "m1" in row["result_preview"]
    assert "https://mail.test/m1" in row["result_preview"]


def test_structure_survives_redaction(tmp_path):
    row = _row(tmp_path, {"messages": [{"id": "a", "body": "x"}, {"id": "b", "body": "y"}]})
    parsed = json.loads(row["result_preview"])
    assert [m["id"] for m in parsed["messages"]] == ["a", "b"]


def test_ordinary_results_are_untouched(tmp_path):
    row = _row(tmp_path, {"count": 3, "ok": True, "name": "Weekly report"})
    assert json.loads(row["result_preview"]) == {"count": 3, "ok": True, "name": "Weekly report"}


def test_arguments_are_still_sanitized(tmp_path):
    """The pre-existing argument sanitizer must not have regressed."""
    store = AuditStore(tmp_path / "a.db")
    store.append({"tool": "x", "arguments": {"api_key": "shh", "body": "hello"}, "result": {}})
    store.close()
    conn = sqlite3.connect(tmp_path / "a.db")
    args = json.loads(conn.execute("SELECT args FROM audit_events").fetchone()[0])
    conn.close()
    assert args["api_key"] == "[redacted]"
    assert args["body"] == "[redacted body]"


# -- 3. Secret backends and migration -------------------------------------------


class _FakeKeychain:
    """A native store stand-in. The real `KeychainBackend` shells out to macOS `security`,
    which cannot run on the CI/Linux host — so the MIGRATION LOGIC is proven here and the
    macOS round-trip is recorded as unverified in release evidence rather than claimed."""

    name = "keychain"

    def __init__(self, *, fail_write=False, corrupt_readback=False):
        self.items: dict = {}
        self.fail_write = fail_write
        self.corrupt_readback = corrupt_readback
        self.writes = 0

    def available(self):
        return True

    def load(self):
        if self.corrupt_readback:
            return {}
        return json.loads(json.dumps(self.items))

    def save(self, store):
        if self.fail_write:
            raise RuntimeError("keychain locked")
        self.writes += 1
        self.items = json.loads(json.dumps(store))


def _legacy(tmp_path, data):
    path = tmp_path / "secrets.json"
    FileBackend(path).save(data)
    return path


def test_migration_moves_profiles_and_retires_the_legacy_file(tmp_path):
    path = _legacy(tmp_path, {"slack:default": {"token": "t1"}, "gmail:default": {"token": "t2"}})
    kc = _FakeKeychain()
    store = SecretStore(path, backend=kc)

    result = store.migrate_to_backend()

    assert result["status"] == "migrated" and result["migrated"] == 2
    assert store.get("slack:default") == {"token": "t1"}
    assert not path.exists(), "the legacy file is retired"
    retired = list(tmp_path.glob("secrets.json.migrated-*"))
    assert len(retired) == 1, "retired by RENAME — never deleted"
    assert json.loads(retired[0].read_text())["slack:default"] == {"token": "t1"}


def test_a_failed_write_leaves_the_legacy_store_untouched(tmp_path):
    path = _legacy(tmp_path, {"slack:default": {"token": "t1"}})
    store = SecretStore(path, backend=_FakeKeychain(fail_write=True))

    with pytest.raises(MigrationError):
        store.migrate_to_backend()

    assert path.exists()
    assert json.loads(path.read_text())["slack:default"] == {"token": "t1"}


def test_a_readback_mismatch_aborts_before_the_legacy_copy_is_retired(tmp_path):
    """The whole point of the ordering: a write that reports success but does not read back
    must not be the moment the only other copy disappears."""
    path = _legacy(tmp_path, {"slack:default": {"token": "t1"}})
    store = SecretStore(path, backend=_FakeKeychain(corrupt_readback=True))

    with pytest.raises(MigrationError) as excinfo:
        store.migrate_to_backend()

    assert "left in place" in str(excinfo.value)
    assert path.exists() and json.loads(path.read_text())["slack:default"] == {"token": "t1"}


def test_migration_never_clobbers_a_profile_already_native(tmp_path):
    path = _legacy(tmp_path, {"slack:default": {"token": "old"}})
    kc = _FakeKeychain()
    kc.items = {"slack:default": {"token": "new"}}
    store = SecretStore(path, backend=kc)

    store.migrate_to_backend()

    assert store.get("slack:default") == {"token": "new"}


def test_migration_is_idempotent(tmp_path):
    path = _legacy(tmp_path, {"a": {"token": "1"}})
    kc = _FakeKeychain()
    store = SecretStore(path, backend=kc)
    assert store.migrate_to_backend()["status"] == "migrated"
    assert store.migrate_to_backend()["status"] == "nothing-to-migrate"


def test_migration_summary_never_carries_a_value(tmp_path):
    path = _legacy(tmp_path, {"slack:default": {"token": "super-secret-value"}})
    result = SecretStore(path, backend=_FakeKeychain()).migrate_to_backend()
    assert "super-secret-value" not in json.dumps(result)


def test_round_trip_through_the_backend(tmp_path):
    store = SecretStore(tmp_path / "secrets.json", backend=_FakeKeychain())
    store.put("slack:default", {"token": "xoxb-1", "type": "bot"})
    assert store.get("slack:default")["token"] == "xoxb-1"
    assert [s["profile"] for s in store.status()] == ["slack:default"]
    assert store.delete("slack:default") is True
    assert store.get("slack:default") is None


def test_an_unreadable_backend_does_not_look_like_an_empty_store(tmp_path):
    """An empty read would let the next `put` overwrite every other credential."""

    class _Broken:
        name = "keychain"

        def available(self):
            return True

        def load(self):
            raise RuntimeError("keychain locked")

        def save(self, store):
            raise AssertionError("must not be reached")

    path = _legacy(tmp_path, {"slack:default": {"token": "t1"}})
    store = SecretStore(path, backend=_Broken())
    assert store.get("slack:default") == {"token": "t1"}, "falls back to the surviving file"


def test_backend_name_is_reportable_for_release_evidence(tmp_path):
    assert SecretStore(tmp_path / "s.json", backend=FileBackend(tmp_path / "s.json")).backend_name == "file"
    assert SecretStore(tmp_path / "s.json", backend=_FakeKeychain()).backend_name == "keychain"


def test_keychain_backend_is_unavailable_off_macos(monkeypatch):
    monkeypatch.setattr("coworker.secrets.sys.platform", "linux")
    assert KeychainBackend().available() is False


def test_high_sensitivity_connectors_stay_off_until_the_native_round_trip_passes():
    """The gate, not a promise: this build has not proven native storage on the launch
    platform, so the capability ships OFF."""
    from coworker import capabilities

    assert capabilities.enabled("high_sensitivity_connectors") is False
