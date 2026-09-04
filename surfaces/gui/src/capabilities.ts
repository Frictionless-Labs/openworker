// Capability gates (OWH M10 §CapabilityGate).
//
// Frictionless ships fail-closed: a capability whose dedicated acceptance gate has not
// passed is OFF, and no unrelated green suite may turn it on. These are compile-time
// constants rather than runtime settings on purpose — a pilot build must not be able to
// drift into a wider posture through a config file the operator can be talked into editing.
//
// Flipping one to `true` is a release decision recorded in docs/security/RELEASE_EVIDENCE.md
// with the prerequisite check that earned it, authorized by the change authority. Do not
// flip one to make a test pass.

export type CapabilityName =
  | "spreadsheetPreview"
  | "activeHtmlPreview"
  | "remoteMcp"
  | "connectorWrites"
  | "unattendedScheduler"
  | "browserAutomation";

/** Prerequisite gate for each capability, quoted in the UI refusal and in release evidence. */
export const CAPABILITY_PREREQUISITE: Record<CapabilityName, string> = {
  spreadsheetPreview: "OW-SEC-002 (M02): hostile-workbook corpus green",
  activeHtmlPreview: "OW-SEC-017 (M08): CSP + artifact isolation corpus green",
  remoteMcp: "OW-SEC-009 (M05): MCP OAuth endpoint corpus green",
  connectorWrites: "OW-SEC-004/005/007 (M03+M04): approval + egress corpora green",
  unattendedScheduler: "OW-SEC-004/005/007/015 (M03+M04+M07) green",
  browserAutomation: "OW-SEC-010 (M05): per-hop prevention, not post-hoc detection",
};

const ENABLED: Record<CapabilityName, boolean> = {
  spreadsheetPreview: false,
  activeHtmlPreview: false,
  remoteMcp: false,
  connectorWrites: false,
  unattendedScheduler: false,
  browserAutomation: false,
};

export function capabilityEnabled(name: CapabilityName): boolean {
  return ENABLED[name] === true;
}
