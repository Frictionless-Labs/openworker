// OW-SEC-017 / D-4: the active-HTML-preview capability gate actually gates.
//
// The E2E suite proves the sandbox is airtight while the preview is ON. This proves the
// gate itself works in BOTH positions — otherwise "it is behind a capability flag" is a
// claim nobody has tested, and a flag that controls nothing reads as a control in review
// and enforces nothing.
//
// The flag is flipped by mocking the module here, at test time. It is deliberately NOT
// readable from the environment or from config in the product: a gate a test can reach
// through a runtime backdoor is a gate an attacker can reach the same way.

import { act, cleanup, render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OPEN_ARTIFACT_EVENT } from "./Markdown";
import { RightRail } from "./RightRail";

let htmlPreviewEnabled = true;

vi.mock("../capabilities", async () => {
  const actual: any = await vi.importActual("../capabilities");
  return {
    ...actual,
    capabilityEnabled: (name: string) =>
      name === "activeHtmlPreview"
        ? htmlPreviewEnabled
        : actual.capabilityEnabled(name),
  };
});

vi.mock("../api", async () => {
  const actual: any = await vi.importActual("../api");
  return {
    ...actual,
    getArtifacts: vi.fn().mockResolvedValue([]),
    getRoots: vi.fn().mockResolvedValue([]),
    getJournalCases: vi.fn().mockResolvedValue([]),
    readArtifact: vi.fn().mockResolvedValue({
      ok: true,
      path: "report.html",
      kind: "html",
      content: "<p>hostile report</p><script>window.x=1</script>",
    }),
    revealArtifact: vi.fn().mockResolvedValue({ ok: true }),
  };
});

async function openHtmlArtifact() {
  const view = render(
    <RightRail
      active
      sessionId="s1"
      refreshKey={0}
      toolNames={[]}
      todo={[]}
      running={false}
      onPreviewChange={() => {}}
    />,
  );
  await act(async () => {
    window.dispatchEvent(
      new CustomEvent(OPEN_ARTIFACT_EVENT, { detail: { path: "report.html" } }),
    );
  });
  return view;
}

describe("active HTML preview capability gate", () => {
  beforeEach(() => {
    // This project does not enable testing-library's auto-cleanup, so without this each
    // render accumulates in document.body and the queries match across tests.
    cleanup();
    htmlPreviewEnabled = true;
  });

  it("renders the sandboxed frame when the capability is ON (ratified 2026-11-23)", async () => {
    const { queryByTestId } = await openHtmlArtifact();
    const frame = queryByTestId("artifact-frame");
    expect(frame).not.toBeNull();
    // The sandbox attribute is the control; assert it here too so the gate and the
    // isolation can never drift apart in one edit.
    expect(frame!.getAttribute("sandbox")).toBe("allow-scripts");
    expect(queryByTestId("html-preview-disabled")).toBeNull();
  });

  it("renders no frame at all when the capability is OFF", async () => {
    htmlPreviewEnabled = false;
    const { queryByTestId } = await openHtmlArtifact();
    expect(queryByTestId("artifact-frame")).toBeNull();
    expect(queryByTestId("html-preview-disabled")).not.toBeNull();
  });

  it("puts no hostile markup in the DOM when the capability is OFF", async () => {
    htmlPreviewEnabled = false;
    const { container } = await openHtmlArtifact();
    // Not merely "the iframe is absent": the content must not have reached the document
    // through some other path either.
    expect(container.innerHTML).not.toContain("hostile report");
    expect(container.querySelector("iframe")).toBeNull();
  });
});
