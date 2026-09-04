"""M03 approval-authority corpus (OW-SEC-003/004/005).

The invariant under test: **a denial, an ambiguous reply, an external actor, an
unrecognised transport, a stale reply, a duplicate reply, or a malformed approval can never
create authorization.** Every row that is not an unambiguous allow from a bound owner must
leave the item pending or deny it.

Table-driven on purpose. The defect class this guards against (upstream's substring match
turning "disallow" into allow, then whole-word matching turning "I cannot approve this" into
allow) is a *parser* defect, and parser defects are found by breadth of input, not by depth
of scenario.
"""

from __future__ import annotations

import pytest

from coworker.engine import ApprovalOutcome
from coworker.inbox import (
    ORIGIN_IN_APP,
    ORIGIN_TRANSPORT,
    PROTECTED_KINDS,
    InboxStore,
    inbox_approver,
)
from coworker.inbox_routing import TRANSPORT_OUTCOMES, resolve_from_reply
from coworker.server.manager import SessionManager


# -- 1. Transport reply ceiling on PROTECTED items ------------------------------

# (label, reply body, expected resolution or None when it must stay pending)
REPLY_CORPUS: list[tuple[str, str, str | None]] = [
    # Unambiguous decisions — the two things a transport may say.
    ("explicit allow", "approve", "allow"),
    ("explicit allow word", "yes", "allow"),
    ("allow emoji", "\U0001f44d", "allow"),
    ("explicit deny", "deny", "deny"),
    ("explicit deny word", "no", "deny"),
    ("deny emoji", "❌", "deny"),
    ("allow with trailing prose", "Yes, go ahead and do it", "allow"),
    ("deny with trailing prose", "No. not right now", "deny"),
    # Negation — the upstream regression this locks down.
    ("negated allow", "I cannot approve this yet", None),
    ("negated allow 2", "not allowed", None),
    ("negated allow 3", "don't approve that", None),
    ("substring trap", "disallow", None),
    ("substring trap 2", "note this for later", None),
    # Mixed / ambiguous intent.
    ("mixed intent", "maybe approve but also deny", None),
    ("question back", "why does it need this?", None),
    ("empty body", "", None),
    ("whitespace only", "   ", None),
    # Persistent-grant escalation (OW-SEC-005).
    ("persistent always", "always", None),
    ("persistent always_tool", "always_tool", None),
    ("persistent phrase", "always allow this tool", None),
    ("persistent trust", "trust this tool from now on", None),
    ("persistent forever", "forever", None),
    ("persistent allowlist", "allowlist it", None),
]


@pytest.mark.parametrize("label,body,expected", REPLY_CORPUS, ids=[r[0] for r in REPLY_CORPUS])
@pytest.mark.parametrize("kind", sorted(PROTECTED_KINDS))
def test_protected_item_reply_ceiling(tmp_path, label, body, expected, kind):
    store = InboxStore(tmp_path / f"inbox-{kind}.json")
    item = store.add_approval("s1", "Run `write_file`?")
    item.kind = kind  # exercise every protected kind through the same ceiling

    resolve_from_reply(
        f"{body} [ow:{item.id}]".strip(),
        store.resolve,
        item_kind=lambda _id: kind,
    )

    got = store.get(item.id)
    if expected is None:
        assert got.state == "pending", f"{label}: must NOT resolve a protected item"
        assert got.resolution is None
    else:
        assert got.resolution == expected, label
        assert got.resolution in TRANSPORT_OUTCOMES


def test_free_text_still_answers_a_question(tmp_path):
    """The ceiling is for protected items only — questions keep their free-text answers."""
    store = InboxStore(tmp_path / "inbox.json")
    q = store.add_question("s1", "Which region?")
    resolve_from_reply(
        f"us-east-1 [ow:{q.id}]", store.resolve, item_kind=lambda _id: "question"
    )
    assert store.get(q.id).resolution == "us-east-1"


def test_malformed_item_id_resolves_nothing(tmp_path):
    store = InboxStore(tmp_path / "inbox.json")
    item = store.add_approval("s1", "Run `write_file`?")
    for reply in (
        "approve [ow:deadbeefcafe]",  # well-formed token, unknown item
        "approve [ow:zz]",  # too short to match the token pattern
        "approve [ow:]",
        "approve ow:%s" % item.id,  # no brackets
        "approve",  # no token at all
    ):
        resolve_from_reply(reply, store.resolve, item_kind=lambda _id: "approval")
    assert store.get(item.id).state == "pending"


def test_stale_and_duplicate_replies_are_idempotent(tmp_path):
    """First responder wins; a later reply cannot overturn or re-grant."""
    store = InboxStore(tmp_path / "inbox.json")
    item = store.add_approval("s1", "Run `write_file`?")
    kind = lambda _id: "approval"  # noqa: E731

    assert resolve_from_reply(f"deny [ow:{item.id}]", store.resolve, item_kind=kind) is True
    # A duplicate, and then a late "approve" from someone who saw the old message.
    assert resolve_from_reply(f"deny [ow:{item.id}]", store.resolve, item_kind=kind) is False
    assert resolve_from_reply(f"approve [ow:{item.id}]", store.resolve, item_kind=kind) is False
    assert store.get(item.id).resolution == "deny"


# -- 2. Durable trust is in-app only (OW-SEC-005) -------------------------------


async def _outcome_for(store: InboxStore, resolution: str, origin: str) -> ApprovalOutcome:
    import asyncio

    approve = inbox_approver(store, "s1")

    class _Request:
        tool_name = "write_file"
        reason = "write a report"

    task = asyncio.ensure_future(approve(_Request()))
    for _ in range(200):
        pending = store.pending("s1")
        if pending:
            break
        await asyncio.sleep(0.005)
    assert pending, "approver did not create an inbox item"
    store.resolve(pending[0].id, resolution, origin=origin)
    return await task


async def test_transport_always_denies_it_does_not_downgrade(tmp_path):
    store = InboxStore(tmp_path / "inbox.json")
    outcome = await _outcome_for(store, "always", ORIGIN_TRANSPORT)
    assert outcome is ApprovalOutcome.DENY


async def test_in_app_always_mints_durable_trust(tmp_path):
    store = InboxStore(tmp_path / "inbox.json")
    outcome = await _outcome_for(store, "always", ORIGIN_IN_APP)
    assert outcome is ApprovalOutcome.ALWAYS_TOOL


async def test_transport_allow_is_one_shot(tmp_path):
    store = InboxStore(tmp_path / "inbox.json")
    outcome = await _outcome_for(store, "allow", ORIGIN_TRANSPORT)
    assert outcome is ApprovalOutcome.ONCE


async def test_legacy_item_without_origin_cannot_mint_durable_trust(tmp_path):
    """An item persisted before `resolution_origin` existed reads as transport-grade."""
    store = InboxStore(tmp_path / "inbox.json")
    outcome = await _outcome_for(store, "always", None)
    assert outcome is ApprovalOutcome.DENY


def test_resolve_records_its_origin(tmp_path):
    store = InboxStore(tmp_path / "inbox.json")
    a = store.add_approval("s1", "a")
    b = store.add_approval("s1", "b")
    store.resolve(a.id, "allow", origin=ORIGIN_TRANSPORT)
    store.resolve(b.id, "allow")  # in-app callers need not say so
    assert store.get(a.id).resolution_origin == ORIGIN_TRANSPORT
    assert store.get(b.id).resolution_origin == ORIGIN_IN_APP


def test_origin_survives_a_restart(tmp_path):
    path = tmp_path / "inbox.json"
    store = InboxStore(path)
    item = store.add_approval("s1", "a")
    store.resolve(item.id, "always", origin=ORIGIN_TRANSPORT)
    assert InboxStore(path).get(item.id).resolution_origin == ORIGIN_TRANSPORT


# -- 3. Actor / transport binding is deny-first for every transport -------------


class _Source:
    def __init__(self, platform, user_id="u-owner", chat_id="T1:C1", team_id="T1"):
        self.platform = platform
        self.user_id = user_id
        self.chat_id = chat_id
        self.team_id = team_id


class _FakeManager:
    """Exercises the real dispatch with a stubbed Slack owner check."""

    def __init__(self, slack_owns: bool):
        self._slack_owns = slack_owns
        self.slack_calls = 0

    def _slack_actor_owns_item(self, item, *, actor_id, chat_id, team_id):
        self.slack_calls += 1
        return self._slack_owns

    _transport_actor_owns_item = SessionManager._transport_actor_owns_item


@pytest.mark.parametrize(
    "platform,slack_owns,expected",
    [
        ("slack", True, True),  # bound owner on the transport that has an owner check
        ("slack", False, False),  # wrong actor / wrong channel
        ("telegram", True, False),  # no owner identity → deny, whatever Slack would say
        ("discord", True, False),  # a transport nobody has vetted
        ("", True, False),  # unknown / spoofed-empty platform
        (None, True, False),
    ],
)
def test_transport_actor_binding_is_deny_first(platform, slack_owns, expected):
    mgr = _FakeManager(slack_owns)
    item = type("Item", (), {"kind": "approval", "inbox": "default"})()
    assert mgr._transport_actor_owns_item(item, _Source(platform)) is expected
    # The Slack path must be the ONLY one that consults the Slack owner list.
    assert mgr.slack_calls == (1 if platform == "slack" else 0)
