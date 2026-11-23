// Capability gates (OWH M10 §CapabilityGate) — the GUI half.
//
// Frictionless ships fail-closed: a capability whose dedicated acceptance gate has not
// passed is OFF, and no unrelated green suite may turn it on. These are compile-time
// constants rather than runtime settings on purpose — a pilot build must not be able to
// drift into a wider posture through a config file the operator can be talked into editing.
//
// Turning one ON is a release decision, so an enabled capability must carry WHO authorized
// it and WHEN. That pairing is enforced by capabilities.test.ts and by the backend's
// tests/test_capability_defaults.py, which also checks the two tables agree: a build whose
// backend says OFF and whose UI says ON is not a build anyone reasoned about.
//
// Never flip one to make a test pass.

export type CapabilityName =
  | "spreadsheetPreview"
  | "activeHtmlPreview"
  | "remoteMcp"
  | "connectorWrites"
  | "unattendedScheduler"
  | "browserAutomation";

export type CapabilityState = {
  enabled: boolean;
  /** The finding whose evidence would earn this gate; quoted in UI refusals. */
  prerequisite: string;
  /** Required when enabled: the decision that actually turned it on. */
  authorizedBy?: string;
  authorizedAt?: string;
  note?: string;
};

export const CAPABILITIES: Record<CapabilityName, CapabilityState> = {
  // Authorized 2026-11-23 (decision D-1).
  spreadsheetPreview: {
    enabled: true,
    prerequisite: "OW-SEC-002 (M02): hostile-workbook corpus green",
    authorizedBy: "Mikkoh Chen",
    authorizedAt: "2026-11-23",
    note: "17/17 hostile-workbook cases; xlsx@0.18.5 gone from the lock; npm audit clean.",
  },
  // Authorized 2026-11-23 (decision D-4), with a disclosed gap: the application CSP's
  // shape is locked but its behaviour in the real Tauri webview is unverified here.
  activeHtmlPreview: {
    enabled: true,
    prerequisite: "OW-SEC-017 (M08): CSP + artifact isolation corpus green",
    authorizedBy: "Mikkoh Chen",
    authorizedAt: "2026-11-23",
    note: "Sandbox proven at browser level; functional CSP check needs a desktop build.",
  },
  // Locked OFF through the restricted pilot (D-2, D-3) even though their corpora are
  // green: the strategy's launch checklist locks them, and evidence earns a capability the
  // right to be considered, not the right to be on.
  remoteMcp: {
    enabled: false,
    prerequisite: "OW-SEC-009 (M05): MCP OAuth endpoint corpus green",
    note: "D-2: prerequisite met; locked OFF through the pilot.",
  },
  connectorWrites: {
    enabled: false,
    prerequisite: "OW-SEC-004/005/007 (M03+M04): approval + egress corpora green",
    note: "D-3: prerequisite met; locked OFF through the pilot.",
  },
  unattendedScheduler: {
    enabled: false,
    prerequisite: "OW-SEC-004/005/007/015 (M03+M04+M07) green",
    note: "Partial: M07's native secret round-trip is unverified off macOS.",
  },
  browserAutomation: {
    enabled: false,
    prerequisite: "OW-SEC-010 (M05): per-hop prevention, not post-hoc detection",
    note: "NOT met: the control detects a bad landing, it does not prevent the request.",
  },
};

export function capabilityEnabled(name: CapabilityName): boolean {
  return CAPABILITIES[name]?.enabled === true;
}

export function capabilityPrerequisite(name: CapabilityName): string {
  return CAPABILITIES[name]?.prerequisite ?? "unknown capability";
}
