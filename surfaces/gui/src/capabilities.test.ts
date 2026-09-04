// Capability defaults, GUI half (OWH M10 §CapabilityGate).
//
// The backend has the same assertion in tests/test_capability_defaults.py. Both exist
// because a build whose backend says OFF and whose UI says ON is not a build anyone
// reasoned about — and the two tables are edited from different places.

import { describe, expect, it } from "vitest";
import {
  CAPABILITY_PREREQUISITE,
  capabilityEnabled,
  type CapabilityName,
} from "./capabilities";

const ALL = Object.keys(CAPABILITY_PREREQUISITE) as CapabilityName[];

describe("capability defaults", () => {
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

  it.each(ALL)("ships '%s' OFF", (name) => {
    expect(capabilityEnabled(name)).toBe(false);
  });

  it.each(ALL)("makes '%s' cite the finding that would enable it", (name) => {
    expect(CAPABILITY_PREREQUISITE[name]).toMatch(/OW-(SEC|REL)-\d{3}/);
  });

  it("fails closed on an unknown name", () => {
    expect(capabilityEnabled("not-a-capability" as CapabilityName)).toBe(false);
  });
});
