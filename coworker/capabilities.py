"""Capability gates (OWH M10 §CapabilityGate) — the backend half.

Frictionless ships fail-closed: a capability whose dedicated acceptance gate has not been
proven is OFF, and passing an unrelated suite does not turn it on. The mirror of this table
lives in `surfaces/gui/src/capabilities.ts`; both are compile-time constants rather than
runtime settings on purpose — a pilot build must not be able to widen its own posture
through a config file the operator can be talked into editing, which is the same reasoning
that puts `config.toml` behind `permissions.protected_paths()`.

Turning one ON is a release decision, so an enabled capability must carry WHO authorized it
and WHEN, and that pairing is enforced by `tests/test_capability_defaults.py`. A bare
`enabled=True` fails CI. The point is not ceremony: an unauthorized flip is exactly the
change that would otherwise slip through review looking like a one-word diff.

Never flip one to make a test pass.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    """One gate. `prerequisite` names the finding whose evidence would earn it; the
    authorization fields record the decision that actually did."""

    enabled: bool
    prerequisite: str
    authorized_by: str = ""
    authorized_at: str = ""
    note: str = ""


CAPABILITIES: dict[str, Capability] = {
    # -- Authorized 2026-11-23 (decisions D-1 and D-4) -------------------------
    "spreadsheet_preview": Capability(
        enabled=True,
        prerequisite="OW-SEC-002 (M02): hostile-workbook corpus green",
        authorized_by="Mikkoh Chen",
        authorized_at="2026-11-23",
        note=(
            "D-1. xlsx@0.18.5 removed from package.json AND package-lock.json; "
            "read-excel-file@9.3.10 behind a bounded adapter; 17/17 hostile-workbook "
            "cases; npm audit 0 vulnerabilities. Legacy .xls is refused by magic-byte "
            "sniff rather than handed to a second binary parser."
        ),
    ),
    "active_html_preview": Capability(
        enabled=True,
        prerequisite="OW-SEC-017 (M08): CSP and artifact isolation corpus green",
        authorized_by="Mikkoh Chen",
        authorized_at="2026-11-23",
        note=(
            "D-4, authorized with a disclosed gap. The sandbox is proven at browser "
            "level (opaque origin; parent DOM, launch token, Tauri IPC and own storage "
            "all unreachable) and the application CSP is non-null with its shape locked. "
            "The CSP's FUNCTIONAL behaviour is unverified: tauri.conf.json is applied by "
            "the Tauri webview, and the E2E suite runs against Vite in a plain browser. "
            "Gating this OFF would have deleted the strongest regression lock in the "
            "corpus, which is why it was ratified rather than disabled."
        ),
    ),
    # -- Locked OFF through the restricted pilot --------------------------------
    #
    # D-2 and D-3. The prerequisites are MET — the corpora are green — and these stay OFF
    # anyway, because the strategy's own launch checklist locks them for the pilot
    # ("Keep remote MCP/write connectors/unattended OFF | Must | Locked"). Evidence earns a
    # capability the right to be considered; it does not enable it.
    "remote_mcp": Capability(
        enabled=False,
        prerequisite="OW-SEC-009 (M05): MCP OAuth endpoint corpus green",
        note="D-2: prerequisite met; locked OFF through the restricted pilot.",
    ),
    "connector_writes": Capability(
        enabled=False,
        prerequisite="OW-SEC-004/005/007 (M03+M04): approval and egress corpora green",
        note="D-3: prerequisite met; locked OFF through the restricted pilot.",
    ),
    "unattended_scheduler": Capability(
        enabled=False,
        prerequisite="OW-SEC-004/005/007/015 (M03+M04+M07) green",
        note=(
            "Partial: M07's native secret round-trip is unverified off macOS, and "
            "unattended execution is the capability that most needs it."
        ),
    ),
    # -- Not met ----------------------------------------------------------------
    "browser_automation": Capability(
        enabled=False,
        prerequisite="OW-SEC-010 (M05): per-hop prevention, not post-hoc detection",
        note=(
            "NOT met. `redirect_refusal` runs after the request has left the machine: it "
            "stops the agent reading the landed page, not the request. Closing this needs "
            "a proxy that vets every hop."
        ),
    ),
    "high_sensitivity_connectors": Capability(
        enabled=False,
        prerequisite="OW-SEC-015/016 (M07): audit redaction and native secret round-trip",
        note=(
            "Partial. Audit redaction is proven against the persisted SQLite rows. The "
            "macOS Keychain round-trip has NOT been executed — `SecretStore.backend_name` "
            "must report 'keychain' before this is considered."
        ),
    ),
}


def enabled(name: str) -> bool:
    """True only for a capability explicitly turned on. An UNKNOWN name is False — a typo
    must fail closed, never open a gate that was never reviewed."""
    capability = CAPABILITIES.get(name)
    return capability is not None and capability.enabled


def prerequisite(name: str) -> str:
    capability = CAPABILITIES.get(name)
    return capability.prerequisite if capability else "unknown capability"


def authorization(name: str) -> str:
    """Who turned this on and when, or `""` for a capability that is off. Release evidence
    quotes this; an enabled capability without it fails CI."""
    capability = CAPABILITIES.get(name)
    if capability is None or not capability.enabled:
        return ""
    return f"{capability.authorized_by} on {capability.authorized_at}".strip()


def require(name: str) -> None:
    """Raise `PermissionError` unless the capability is on. The message names the gate that
    would have to pass, so a refusal tells the operator what is missing rather than only
    that something is off."""
    if not enabled(name):
        raise PermissionError(
            f"capability '{name}' is disabled in this build "
            f"(prerequisite: {prerequisite(name)})"
        )
