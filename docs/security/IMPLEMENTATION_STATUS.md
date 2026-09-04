# Implementation Status

Read this file first in any resumed session, after `CLAUDE.md`, `SPEC.md`, and `docs/RUNBOOK.md`.

| Field | Value |
|---|---|
| Baseline | `5bc10d928e0b64aae74313349a3b17bd19643ae2` on `claude/openworker-hardened-adoption-m7iwq6` |
| Phase | GUIDE |
| Module | M03 Approval Authority — **PASS** |
| Changed files | M02: `uv.lock`, `pyproject.toml`, `.github/workflows/{ci,release}.yml`, `surfaces/gui/package.json`, `surfaces/gui/package-lock.json`, `surfaces/gui/playwright.config.ts`, `surfaces/gui/src/capabilities.ts`, `surfaces/gui/src/sheet/{parser,testWorkbook,parser.test}.ts`, `surfaces/gui/src/components/RightRail.tsx`, `surfaces/gui/src/locales/{en,zh}.json` · M03: `coworker/inbox.py`, `coworker/inbox_routing.py`, `coworker/server/manager.py`, `tests/test_approval_authority.py` |
| Tests | pytest **2039 passed, 1 skipped, 0 failed** · GUI unit **198/198** · GUI E2E **221/221** · `npx tsc --noEmit` clean · `npm run build` OK · `cargo test stt` **4 passed** · `cargo check` Tauri OK · `uv lock --check` clean · `npm audit --omit=dev` **0 vulnerabilities** |
| Findings | CLOSED: OW-SEC-001, OW-SEC-002, OW-SEC-003, OW-SEC-004, OW-SEC-005. Open: OW-SEC-006..017, OW-REL-001 |
| Decisions | None required from Mikkoh yet |
| Next step | Implement M04 Provenance + Egress (`TrustOrigin` + egress gate) |

## M01 acceptance booleans

- [x] Historical snapshot ref resolves to `01b6f83b3927e02912dda84bb392942c13ca70d1`
- [x] Hardening base resolves to `5bc10d928e0b64aae74313349a3b17bd19643ae2`
- [x] Every downstream patch row has a finding ID, tests, upstream status, and removal condition
- [x] No undocumented downstream security delta (0 downstream-only commits)

## Module ledger

| Module | State |
|---|---|
| M01 Baseline + Patch Ledger | PASS |
| M02 Supply Chain + Spreadsheet Parser | PASS |
| M03 Approval Authority | PASS |
| M04 Provenance + Egress | NOT STARTED |
| M05 MCP + Browser Network Guard | NOT STARTED |
| M06 Files + Shell Confinement | NOT STARTED |
| M07 Audit + Secrets | NOT STARTED |
| M08 Artifact Isolation + CSP | NOT STARTED |
| M09 Durable State | NOT STARTED |
| M10 CI + Release Gate | NOT STARTED |


## Environment notes for whoever resumes this

Two sandbox artifacts, neither of which is a repository defect:

| Symptom | Cause | Workaround used for evidence |
|---|---|---|
| 7 pytest failures in `tests/test_fake_slack.py` and `tests/test_ui_refresh_e2e.py` | The container's `HTTPS_PROXY` is applied to **loopback** WebSocket/HTTP traffic, and the relay answers 405 to plain HTTP | Run with the proxy vars cleared. These tests only talk to `127.0.0.1`, so nothing leaves the machine: `env -u HTTPS_PROXY -u https_proxy -u GLOBAL_AGENT_HTTPS_PROXY -u YARN_HTTPS_PROXY -u DOCKER_HTTPS_PROXY uv run --locked pytest tests -q`. All 7 pass. |
| Playwright cannot launch: `chromium_headless_shell-1228` missing | The image ships Chromium build 1194 and has no egress to fetch another | `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium npm run e2e` (config support added in M02) |

Rust builds additionally need `libasound2-dev` (STT) and `libgtk-3-dev libwebkit2gtk-4.1-dev
libsoup-3.0-dev libjavascriptcoregtk-4.1-dev librsvg2-dev` (Tauri) on a Linux host.
