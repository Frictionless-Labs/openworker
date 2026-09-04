// OWH M08 (OW-SEC-017a): the desktop content-security policy.
//
// Tauri's own guidance is that the CSP should be as restrictive as the app's functional
// requirements allow, and that untrusted files in a webview are an attack vector. The
// baseline shipped `"csp": null`, which is no policy at all.
//
// These assertions are a regression lock on the SHAPE of the policy, not a substitute for
// running it: the config is only applied by the Tauri webview, so a functional check needs
// a desktop build on the launch platform. That limitation is recorded in
// docs/security/RELEASE_EVIDENCE.md rather than papered over here.

import { describe, expect, it } from "vitest";
import config from "./../src-tauri/tauri.conf.json";

const csp: string = (config as any).app.security.csp;

function directive(name: string): string {
  const found = csp
    .split(";")
    .map((d) => d.trim())
    .find((d) => d === name || d.startsWith(name + " "));
  return found ? found.slice(name.length).trim() : "";
}

describe("Tauri content security policy", () => {
  it("is not null", () => {
    expect(csp).toBeTruthy();
    expect(typeof csp).toBe("string");
  });

  it("locks the default down to the bundled app", () => {
    expect(directive("default-src")).toBe("'self'");
  });

  it("whitelists no remote script origin", () => {
    const scriptSrc = directive("script-src");
    expect(scriptSrc).toBeTruthy();
    expect(scriptSrc).not.toMatch(/https?:/);
    expect(scriptSrc).not.toContain("*");
    expect(scriptSrc).not.toContain("'unsafe-eval'");
  });

  it("forbids plugins, base-tag hijacking, form posts, and being framed", () => {
    expect(directive("object-src")).toBe("'none'");
    expect(directive("base-uri")).toBe("'self'");
    expect(directive("form-action")).toBe("'none'");
    expect(directive("frame-ancestors")).toBe("'none'");
  });

  it("permits only the LOCAL sidecar and Tauri IPC as connect targets", () => {
    const connect = directive("connect-src");
    expect(connect).toContain("'self'");
    expect(connect).toContain("http://127.0.0.1:*");
    expect(connect).toContain("ws://127.0.0.1:*");
    // No general remote egress from the privileged app origin.
    expect(connect).not.toMatch(/\bhttps:\s*(;|$)/);
    expect(connect).not.toContain("https://*");
  });

  it("does not let artifact frames load remote documents", () => {
    const frame = directive("frame-src");
    expect(frame).toBeTruthy();
    expect(frame).not.toMatch(/https?:/);
  });

  it("keeps every directive the app depends on present", () => {
    for (const name of [
      "default-src",
      "script-src",
      "style-src",
      "img-src",
      "connect-src",
      "frame-src",
      "object-src",
    ]) {
      expect(directive(name), `missing ${name}`).toBeTruthy();
    }
  });
});
