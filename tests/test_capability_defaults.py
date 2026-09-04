"""Capability defaults (OWH M10 §CapabilityGate).

A capability is earned by evidence, so the interesting failure is not "a gate is missing"
but "a gate was quietly turned on". This file is the check that makes that edit visible: it
runs as its own CI job, and it asserts BOTH halves of the table, because a build whose
backend says OFF and whose UI says ON is not a build anyone reasoned about.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from coworker import capabilities

GUI_TABLE = Path(__file__).resolve().parents[1] / "surfaces/gui/src/capabilities.ts"


@pytest.mark.parametrize("name", sorted(capabilities.CAPABILITIES))
def test_every_capability_ships_off(name):
    assert capabilities.enabled(name) is False, (
        f"'{name}' is ON. Enabling a capability is a release decision recorded in "
        "docs/security/RELEASE_EVIDENCE.md against the check that earned it — not a code "
        "edit, and never a way to make a test pass."
    )


@pytest.mark.parametrize("name", sorted(capabilities.CAPABILITIES))
def test_every_capability_names_its_prerequisite_gate(name):
    prerequisite = capabilities.prerequisite(name)
    assert prerequisite, f"'{name}' must name the gate that would have to pass"
    assert re.search(r"OW-(SEC|REL)-\d{3}", prerequisite), (
        f"'{name}' must cite a finding ID so the refusal points somewhere real"
    )


def test_the_risky_capabilities_named_by_the_strategy_are_all_present():
    """The capability ladder is the release contract; a capability missing from the table
    is one nobody is gating."""
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
    with pytest.raises(PermissionError):
        capabilities.require("typo_in_a_capability_name")


def test_require_names_the_missing_gate():
    with pytest.raises(PermissionError) as excinfo:
        capabilities.require("remote_mcp")
    assert "OW-SEC-009" in str(excinfo.value)


def test_the_gui_table_agrees_with_the_backend():
    """Both halves ship OFF. Parsed rather than executed so this stays a pytest job with no
    Node dependency; the GUI's own vitest suite asserts the same table from the other side.
    """
    source = GUI_TABLE.read_text(encoding="utf-8")
    block = re.search(
        r"const ENABLED: Record<CapabilityName, boolean> = \{(.*?)\};", source, re.S
    )
    assert block, "could not find the GUI capability table"
    flags = dict(re.findall(r"(\w+):\s*(true|false)", block.group(1)))
    assert flags, "the GUI capability table parsed as empty"
    for name, value in flags.items():
        assert value == "false", f"GUI capability '{name}' is ON"
