"""Multi-inbox routing — named inboxes + delivery bindings.

An inbox is a named queue with optional delivery binding(s): in-app is always the store of
record; a binding can also mirror items to a Slack channel or Telegram chat. Sessions route to
an inbox by a per-session override, else the persona's default, else ``"default"``. Bindings
are bidirectional: an item is delivered to the bound channel with its id embedded, and an
inbound reply (correlated by that id) resolves the item — so the connectors/mobile are just
transports of the same items. The gateway wiring is injected (a ``sender`` callable) so this
module stays testable without touching Slack/Telegram.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional

from .inbox import PROTECTED_KINDS
from .jsonstate import read_json_safe, write_json_atomic

DEFAULT_INBOX = "default"
# Embeds the item id in a delivered message. Emitted as [ow:…] since the bot's rebrand
# to OpenWorker (2026-07-22); the legacy [ocw:…] spelling stays parseable so replies to
# messages sent before the rename still resolve.
_ID_TOKEN = re.compile(r"\[o(?:c)?w:([0-9a-f]{6,})\]")


@dataclass
class InboxBinding:
    name: str
    channel: Optional[str] = None  # None (in-app only) | "slack" | "telegram"
    target: str = ""  # channel id / chat id for the binding


class InboxRouting:
    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._bindings: dict[str, InboxBinding] = {
            DEFAULT_INBOX: InboxBinding(DEFAULT_INBOX)
        }
        self._persona_default: dict[str, str] = {}
        self._session_override: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.path:
            return
        data = read_json_safe(self.path, default={}, store="inbox_routing") or {}
        for raw in data.get("bindings", []):
            try:
                b = InboxBinding(**raw)
            except TypeError:
                continue
            self._bindings[b.name] = b
        self._persona_default = dict(data.get("persona_default", {}) or {})
        self._session_override = dict(data.get("session_override", {}) or {})

    def _save(self) -> None:
        if not self.path:
            return
        write_json_atomic(
            self.path,
            {
                "bindings": [asdict(b) for b in self._bindings.values()],
                "persona_default": self._persona_default,
                "session_override": self._session_override,
            },
        )

    # -- config -----------------------------------------------------------------
    def set_binding(
        self, name: str, *, channel: Optional[str] = None, target: str = ""
    ) -> None:
        with self._lock:
            self._bindings[name] = InboxBinding(name, channel, target)
            self._save()

    def binding_for(self, name: str) -> InboxBinding:
        return self._bindings.get(name) or InboxBinding(name)

    def set_persona_default(self, persona_id: str, inbox_name: str) -> None:
        with self._lock:
            self._persona_default[persona_id] = inbox_name
            self._save()

    def set_session_override(self, session_id: str, inbox_name: str) -> None:
        with self._lock:
            self._session_override[session_id] = inbox_name
            self._save()

    # -- resolution -------------------------------------------------------------
    def route_for(self, session_id: str, persona_id: Optional[str] = None) -> str:
        """Per-session override > persona default > the global default inbox."""
        if session_id in self._session_override:
            return self._session_override[session_id]
        if persona_id and persona_id in self._persona_default:
            return self._persona_default[persona_id]
        return DEFAULT_INBOX

    def bindings(self) -> list[dict]:
        return [asdict(b) for b in self._bindings.values()]


# -- delivery + inbound correlation ---------------------------------------------
Sender = Callable[[str, str, str], None]  # (channel, target, text) -> None


def deliver(item, binding: InboxBinding, sender: Optional[Sender]) -> bool:
    """Mirror an inbox item to its bound channel (if any). The item id is embedded so an inbound
    reply can be correlated back. In-app-only bindings deliver nothing here. Returns True if a
    channel message was sent."""
    if not binding.channel or sender is None:
        return False
    text = f"{item.title}\n{item.body}\n[ow:{item.id}]".strip()
    sender(binding.channel, binding.target, text)
    return True


# Decision keywords for a channel reply. Matched against the reply's LEADING word/emoji
# only (see _reply_intent). Substring matching turned "disallow" into allow and "note"
# into deny; whole-word matching anywhere (the interim fix) still inverted negated
# replies — "I cannot approve this yet" matched \bapprove\b and, with allow checked
# first, executed the declined action. Leading-word intent keeps "Yes, go ahead" /
# "No." / "👍" working; everything else is a free-text answer, which the approval path
# already maps to deny — the safe default for an approval gate.
_ALLOW_WORDS = frozenset({"approve", "approved", "allow", "allowed", "yes"})
_DENY_WORDS = frozenset({"deny", "denied", "reject", "rejected", "no"})
_ALLOW_EMOJI = ("👍", "✅")
_DENY_EMOJI = ("👎", "❌")
_TOKEN_TRIM = ".,!?:;'\"()"

# Words that ask for authority OUTLIVING this one call. A transport reply may never mint
# these (OW-SEC-005), and they are listed explicitly rather than left to fall through as
# "free text" so the refusal is a decision the corpus can assert, not an accident of the
# allow/deny tables not containing them.
_PERSISTENT_WORDS = frozenset(
    {
        "always",
        "always_tool",
        "always_command",
        "always_task",
        "forever",
        "permanently",
        "trust",
        "whitelist",
        "allowlist",
    }
)

# The only outcomes a messaging transport may produce. Anything else — free text, a
# persistent-grant keyword, an unrecognised word — leaves a protected item PENDING, which
# is the state the operator can still resolve correctly from the app.
TRANSPORT_OUTCOMES = frozenset({"allow", "deny"})


def _reply_intent(text: str) -> Optional[str]:
    """Allow/deny intent from the first word (or emoji) of a reply, else None.

    `None` means "no decision was expressed", which for a protected item is a refusal (see
    `resolve_from_reply`) and for a question is an ordinary free-text answer. A
    persistent-grant word returns None on purpose: over a transport it is not an allow.
    """
    first = text.split()[0] if text.split() else ""
    if first.startswith(_ALLOW_EMOJI):  # startswith: tolerate skin-tone modifiers
        return "allow"
    if first.startswith(_DENY_EMOJI):
        return "deny"
    word = first.strip(_TOKEN_TRIM).lower()
    if word in _PERSISTENT_WORDS:
        return None
    if word in _ALLOW_WORDS:
        return "allow"
    if word in _DENY_WORDS:
        return "deny"
    return None


def resolve_from_reply(
    reply: str,
    resolve: Callable[[str, str], bool],
    *,
    item_kind: Optional[Callable[[str], Optional[str]]] = None,
) -> Optional[bool]:
    """Correlate an inbound channel reply to its item (by the embedded id) and resolve it.

    Looks for the ``[ow:<id>]`` token (or legacy ``[ocw:…]``) and an allow/deny intent in the
    reply's leading word. ``resolve(item_id, resolution)`` is the InboxStore.resolve.
    Returns the resolve() result, or None if no item id was found.

    ``item_kind(item_id)`` reports the item's kind so a PROTECTED item (approval, directory
    grant, plan) can be held to the transport ceiling (OW-SEC-004/005): its resolution must
    be an unambiguous ``allow``/``deny``. Free text, a mixed or negated sentence, a
    persistent-grant keyword, or an unknown id all leave it PENDING — the operator resolves
    it from the app, where the authority actually lives.

    Passing no ``item_kind`` keeps the pre-existing behaviour for callers that have no store
    to consult (the question/notification path, and tests). Every caller that can resolve a
    protected item MUST pass it.
    """
    m = _ID_TOKEN.search(reply or "")
    if not m:
        return None
    item_id = m.group(1)
    text = _ID_TOKEN.sub("", reply).strip()
    intent = _reply_intent(text)

    kind = None
    if item_kind is not None:
        try:
            kind = item_kind(item_id)
        except Exception:
            kind = None
    if kind is not None and kind in PROTECTED_KINDS:
        if intent not in TRANSPORT_OUTCOMES:
            # Consumed (the token was ours) but deliberately unresolved.
            return False
        return resolve(item_id, intent)

    resolution = intent or text  # free-text answer to a question
    return resolve(item_id, resolution)
