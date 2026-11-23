// Capability gates, GUI half (OWH M10 §CapabilityGate).
//
// The interesting failure is not "a gate is missing" — it is "a gate was quietly turned
// on". So the assertion is not "everything is OFF" (that would have to be weakened the
// first time a capability is legitimately authorized, and a test you weaken is a test you
// stop trusting). It is: nothing is ON without a recorded authorization, and the
// capabilities the strategy locks for the pilot are OFF.
//
// The backend asserts the same table from the other side in
// tests/test_capability_defaults.py, including that the two halves agree.

import { describe, expect, it } from "vitest";
import {
  CAPABILITIES,
  capabilityEnabled,
  capabilityPrerequisite,
  type CapabilityName,
} from "./capabilities";

const ALL = Object.keys(CAPABILITIES) as CapabilityName[];

// Locked OFF for the restricted pilot. D-2/D-3 confirmed these stay off even though their
// prerequisites are met; browserAutomation's prerequisite is not met at all.
const LOCKED_OFF: CapabilityName[] = [
  "remoteMcp",
  "connectorWrites",
  "unattendedScheduler",
  "browserAutomation",
];

describe("capability gates", () => {
  it("gates every risky capability the strategy names", () => {
    for (const name of [
      "spreadsheetPreview",
      "activeHtmlPreview",
      "remoteMcp",
      "connectorWrites",
      "unattendedScheduler",
      "browserAutomation",
    ]) {
      expect(ALL).toContain(name);
    }
  });

  it.each(ALL)("makes '%s' cite the finding that would enable it", (name) => {
    expect(capabilityPrerequisite(name)).toMatch(/OW-(SEC|REL)-\d{3}/);
  });

  it.each(ALL)("never leaves '%s' ON without a recorded authorization", (name) => {
    const state = CAPABILITIES[name];
    if (!state.enabled) return;
    expect(state.authorizedBy, `${name} is ON with no authorizedBy`).toBeTruthy();
    expect(state.authorizedAt, `${name} is ON with no authorizedAt`).toMatch(
      /^\d{4}-\d{2}-\d{2}$/,
    );
  });

  it.each(LOCKED_OFF)("keeps '%s' OFF through the restricted pilot", (name) => {
    expect(capabilityEnabled(name)).toBe(false);
  });

  it("fails closed on an unknown name", () => {
    expect(capabilityEnabled("not-a-capability" as CapabilityName)).toBe(false);
    expect(capabilityPrerequisite("not-a-capability" as CapabilityName)).toBe(
      "unknown capability",
    );
  });

  it("records the authorizations ratified on 2026-11-23", () => {
    // D-1 and D-4. Spelled out so a later silent revert shows up as a failing test
    // rather than as a quiet narrowing nobody notices.
    expect(capabilityEnabled("spreadsheetPreview")).toBe(true);
    expect(capabilityEnabled("activeHtmlPreview")).toBe(true);
  });
});
