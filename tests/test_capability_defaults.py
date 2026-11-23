"""Capability gates (OWH M10 §CapabilityGate).

A capability is earned by evidence, so the interesting failure is not "a gate is missing"
but "a gate was quietly turned on". This file is the check that makes such an edit visible,
and it runs as its own CI job.

It deliberately does NOT assert "everything is OFF". That assertion has to be weakened the
first time a capability is legitimately authorized, and a test you weaken once is a test you
stop trusting. The durable invariants are:

* nothing is ON without a recorded authorization (who, and a real date);
* the capabilities the strategy locks for the restricted pilot are OFF;
* both halves of the table — backend and GUI — agree, because a build whose backend says
  OFF and whose UI says ON is not a build anyone reasoned about.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from coworker import capabilities

GUI_TABLE = Path(__file__).resolve().parents[1] / "surfaces/gui/src/capabilities.ts"

# snake_case backend name -> camelCase GUI name, for the two capabilities both halves hold.
SHARED_NAMES = {
    "spreadsheet_preview": "spreadsheetPreview",
    "active_html_preview": "activeHtmlPreview",
    "remote_mcp": "remoteMcp",
    "connector_writes": "connectorWrites",
    "unattended_scheduler": "unattendedScheduler",
    "browser_automation": "browserAutomation",
}

# Locked OFF through the restricted pilot. D-2/D-3 confirmed that remote MCP and connector
# writes stay off even though their corpora are green — the strategy's launch checklist
# locks them, and evidence earns a capability the right to be CONSIDERED, not to be on.
# browser_automation's prerequisite is not met at all (detection, not prevention).
LOCKED_OFF = (
    "remote_mcp",
    "connector_writes",
    "unattended_scheduler",
    "browser_automation",
    "high_sensitivity_connectors",
)


@pytest.mark.parametrize("name", sorted(capabilities.CAPABILITIES))
def test_nothing_is_on_without_a_recorded_authorization(name):
    capability = capabilities.CAPABILITIES[name]
    if not capability.enabled:
        assert capabilities.authorization(name) == ""
        return
    assert capability.authorized_by, (
        f"'{name}' is ON with no authorized_by. Enabling a capability is a release "
        "decision recorded against the check that earned it — not a code edit, and never "
        "a way to make a test pass."
    )
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", capability.authorized_at or ""), (
        f"'{name}' is ON with no usable authorized_at date"
    )
    assert capabilities.authorization(name)


@pytest.mark.parametrize("name", sorted(capabilities.CAPABILITIES))
def test_every_capability_names_its_prerequisite_gate(name):
    prerequisite = capabilities.prerequisite(name)
    assert prerequisite, f"'{name}' must name the gate that would have to pass"
    assert re.search(r"OW-(SEC|REL)-\d{3}", prerequisite), (
        f"'{name}' must cite a finding ID so the refusal points somewhere real"
    )


@pytest.mark.parametrize("name", LOCKED_OFF)
def test_pilot_locked_capabilities_are_off(name):
    assert name in capabilities.CAPABILITIES, f"{name} is not gated at all"
    assert capabilities.enabled(name) is False, (
        f"'{name}' is locked OFF through the restricted pilot"
    )


def test_the_authorizations_ratified_on_2026_11_23_are_recorded():
    """D-1 and D-4, spelled out so a later silent revert fails a test rather than passing
    as a quiet narrowing nobody notices."""
    for name in ("spreadsheet_preview", "active_html_preview"):
        assert capabilities.enabled(name) is True
        assert "2026-11-23" in capabilities.authorization(name)


def test_the_risky_capabilities_named_by_the_strategy_are_all_present():
    for name in (
        "remote_mcp",
        "connector_writes",
        "unattended_scheduler",
        "active_html_preview",
        "spreadsheet_preview",
        "browser_automation",
        "high_sensitivity_connectors",
    ):
        assert name in capabilities.CAPABILITIES, f"{name} is not gated"


def test_an_unknown_capability_fails_closed():
    assert capabilities.enabled("typo_in_a_capability_name") is False
    assert capabilities.authorization("typo_in_a_capability_name") == ""
    with pytest.raises(PermissionError):
        capabilities.require("typo_in_a_capability_name")


def test_require_names_the_missing_gate():
    with pytest.raises(PermissionError) as excinfo:
        capabilities.require("remote_mcp")
    assert "OW-SEC-009" in str(excinfo.value)


def _gui_flags() -> dict[str, bool]:
    """Parse `name: { ... enabled: true/false ... }` out of the GUI table.

    Parsed rather than executed so this stays a pytest job with no Node dependency; the
    GUI's own vitest suite asserts the same table from the other side.
    """
    source = GUI_TABLE.read_text(encoding="utf-8")
    block = re.search(
        r"export const CAPABILITIES: Record<CapabilityName, CapabilityState> = \{(.*?)\n\};",
        source,
        re.S,
    )
    assert block, "could not find the GUI capability table"
    found = re.findall(r"^  (\w+): \{(.*?)^  \},", block.group(1), re.S | re.M)
    assert found, "the GUI capability table parsed as empty"
    flags: dict[str, bool] = {}
    for name, body in found:
        match = re.search(r"enabled:\s*(true|false)", body)
        assert match, f"GUI capability '{name}' has no enabled flag"
        flags[name] = match.group(1) == "true"
    return flags


def test_the_gui_table_parses():
    flags = _gui_flags()
    assert set(flags) == set(SHARED_NAMES.values()), (
        f"GUI table holds {sorted(flags)}; expected {sorted(SHARED_NAMES.values())}"
    )


@pytest.mark.parametrize("backend_name,gui_name", sorted(SHARED_NAMES.items()))
def test_both_halves_of_the_table_agree(backend_name, gui_name):
    flags = _gui_flags()
    assert capabilities.enabled(backend_name) == flags[gui_name], (
        f"'{backend_name}' is {capabilities.enabled(backend_name)} in the backend but "
        f"'{gui_name}' is {flags[gui_name]} in the GUI — a build whose halves disagree is "
        "not a build anyone reasoned about"
    )
