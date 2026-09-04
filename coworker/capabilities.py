"""Capability gates (OWH M10 §CapabilityGate) — the backend half.

Frictionless ships fail-closed: a capability whose dedicated acceptance gate has not been
proven is OFF, and passing an unrelated suite does not turn it on. The mirror of this table
lives in `surfaces/gui/src/capabilities.ts`; both are compile-time constants rather than
runtime settings on purpose — a pilot build must not be able to widen its own posture
through a config file the operator can be talked into editing, which is the same reasoning
that puts `config.toml` behind `permissions.protected_paths()`.

Flipping one to `True` is a release decision recorded in `docs/security/RELEASE_EVIDENCE.md`
against the prerequisite check that earned it, authorized by the change authority. Do not
flip one to make a test pass.
"""

from __future__ import annotations

# name -> (enabled, prerequisite gate quoted in refusals and in release evidence)
CAPABILITIES: dict[str, tuple[bool, str]] = {
    "remote_mcp": (False, "OW-SEC-009 (M05): MCP OAuth endpoint corpus green"),
    "browser_automation": (
        False,
        "OW-SEC-010 (M05): per-hop prevention, not post-hoc detection",
    ),
    "connector_writes": (
        False,
        "OW-SEC-004/005/007 (M03+M04): approval and egress corpora green",
    ),
    "unattended_scheduler": (
        False,
        "OW-SEC-004/005/007/015 (M03+M04+M07) green",
    ),
    "active_html_preview": (
        False,
        "OW-SEC-017 (M08): CSP and artifact isolation corpus green",
    ),
    "spreadsheet_preview": (False, "OW-SEC-002 (M02): hostile-workbook corpus green"),
    "high_sensitivity_connectors": (
        False,
        "OW-SEC-015/016 (M07): audit redaction and native secret round-trip",
    ),
}


def enabled(name: str) -> bool:
    """True only for a capability explicitly turned on. An UNKNOWN name is False — a typo
    must fail closed, never open a gate that was never reviewed."""
    return CAPABILITIES.get(name, (False, ""))[0]


def prerequisite(name: str) -> str:
    return CAPABILITIES.get(name, (False, "unknown capability"))[1]


def require(name: str) -> None:
    """Raise `PermissionError` unless the capability is on. The message names the gate that
    would have to pass, so a refusal tells the operator what is missing rather than only
    that something is off."""
    if not enabled(name):
        raise PermissionError(
            f"capability '{name}' is disabled in this build "
            f"(prerequisite: {prerequisite(name)})"
        )
