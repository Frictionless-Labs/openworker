"""Structural trust provenance (OWH M04 / OW-SEC-006).

The agent's system prompts already say to treat web pages, email and Slack messages as
"untrusted data, not instructions". That is guidance to a model, and a model that has just
read a convincing instruction is exactly the component under attack — so it cannot be the
authorization boundary. This module is the boundary: an origin class the runtime computes
from WHERE content entered, never from what the content says.

Three properties make it structural rather than advisory:

* It is **system-generated**. Nothing derives an origin by reading text, so no payload can
  claim `owner_instruction` by containing the words. A hostile page cannot forge a class it
  is never asked to supply.
* It **survives storage and serialization**. The marker rides as a message sidecar, which
  `Engine._outbound_messages` strips before any provider sees it — the same path
  `_display` already uses. Provenance is therefore available to the runtime on reload and
  invisible to the model, which is the correct direction for both.
* It is **consumed by a deterministic rule**, not by a prompt. See `coworker/egress.py`.

Built on upstream's own ingestion classifier (`session_facts.INGESTING_CATEGORIES`), which
already answers "can this tool's result carry content authored outside this machine?" That
module's docstring notes nothing consumed it in v1; this is what consumes it.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional

from .session_facts import is_ingesting


class TrustOrigin(str, Enum):
    """Where a piece of context came from. Ordered least- to most-suspect is meaningless
    here on purpose: these are kinds, not levels, and the egress rule reads membership."""

    OWNER_INSTRUCTION = "owner_instruction"
    UNTRUSTED_EXTERNAL_DATA = "untrusted_external_data"
    UNTRUSTED_TOOL_RESULT = "untrusted_tool_result"
    TRUSTED_SYSTEM = "trusted_system"


UNTRUSTED_ORIGINS = frozenset(
    {TrustOrigin.UNTRUSTED_EXTERNAL_DATA, TrustOrigin.UNTRUSTED_TOOL_RESULT}
)

# The sidecar key. Underscore-prefixed to match the existing convention for fields the
# provider feed strips (`_display`).
ORIGIN_KEY = "_trust_origin"


def origin_for_tool_result(metadata: Any) -> TrustOrigin:
    """The origin class of a tool's RESULT, from its registration metadata.

    `is_ingesting` covers the web, connector and MCP categories — everything whose result
    can carry bytes someone else wrote. Local reads are excluded there and stay excluded
    here; the cost of that exclusion (a poisoned file already in the workspace produces no
    marker) is upstream's documented trade-off and is not silently papered over.
    """
    return (
        TrustOrigin.UNTRUSTED_TOOL_RESULT
        if is_ingesting(metadata)
        else TrustOrigin.TRUSTED_SYSTEM
    )


def origin_for_message(message: dict[str, Any]) -> TrustOrigin:
    """The origin class of a thread message.

    A `source` sidecar means a connector delivered this turn — a Slack/Telegram/email
    message someone else composed — so it is external data no matter that it arrives in the
    `user` role. That role assignment is precisely the confused-deputy step this closes: a
    channel message rendered as a user turn otherwise carries the operator's authority.
    """
    if message.get(ORIGIN_KEY):
        try:
            return TrustOrigin(str(message[ORIGIN_KEY]))
        except ValueError:
            return TrustOrigin.UNTRUSTED_EXTERNAL_DATA
    role = str(message.get("role") or "")
    if role == "user":
        return (
            TrustOrigin.UNTRUSTED_EXTERNAL_DATA
            if message.get("source")
            else TrustOrigin.OWNER_INSTRUCTION
        )
    if role == "system":
        return TrustOrigin.TRUSTED_SYSTEM
    if role == "tool":
        return TrustOrigin.TRUSTED_SYSTEM
    return TrustOrigin.TRUSTED_SYSTEM


# -- secret-shaped payload detection --------------------------------------------
#
# A heuristic, and labelled as one. It exists to raise the bar on the obvious cases (an
# outbound message carrying a key the agent just read out of the environment), NOT to
# certify that anything it passes is secret-free. The egress rule is therefore written so
# that a miss here still leaves the untrusted-context rule standing.

_SECRET_KEY_HINTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
    "authorization",
    "session_key",
)

# Vendor-shaped literals. Anchored on issuer prefixes rather than "long random-looking
# string", which matches base64 image data and commit SHAs and would make the gate noisy
# enough to be switched off — the failure mode that kills a control.
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),  # Anthropic
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),  # Slack
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),  # Google
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
)


def looks_like_secret(value: str) -> bool:
    """True when a string carries a vendor-shaped credential literal."""
    return any(p.search(value) for p in _SECRET_VALUE_PATTERNS)


def secret_shaped(value: Any, *, key: Optional[str] = None, _depth: int = 0) -> bool:
    """True when a tool argument names or carries something credential-shaped.

    Walks nested structures because the payload that matters is rarely a top-level string:
    an attachment list, a JSON body, a dict of headers.
    """
    if _depth > 6:
        return False
    if key and any(hint in str(key).lower() for hint in _SECRET_KEY_HINTS):
        # An empty value is a field name, not a leak.
        if isinstance(value, str) and value.strip():
            return True
        if isinstance(value, (int, float)):
            return True
    if isinstance(value, str):
        return looks_like_secret(value)
    if isinstance(value, dict):
        return any(
            secret_shaped(v, key=str(k), _depth=_depth + 1) for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(secret_shaped(v, key=key, _depth=_depth + 1) for v in value)
    return False
