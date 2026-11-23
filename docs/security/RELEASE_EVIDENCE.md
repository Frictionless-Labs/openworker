# Release Evidence — `frictionless-v0.1.0+upstream.5bc10d9`

| Field | Value |
|---|---|
| Candidate | **NOT CUT** — see "Why no tag" below |
| Capability decisions | D-1 … D-6 ratified by Mikkoh Chen on 2026-11-23 |
| Hardening branch | `claude/openworker-hardened-adoption-m7iwq6` |
| Evidence captured at | `8fa7d8a69a2af897c8a17a04d901e4720eca9707` (plus this commit) |
| Upstream baseline | `5bc10d928e0b64aae74313349a3b17bd19643ae2` |
| Historical snapshot | `01b6f83b3927e02912dda84bb392942c13ca70d1` (`archive/snapshot-2026-08-01`) |
| Release status | **NOT RELEASABLE** — four gates are BLOCKED by this environment; human GO not given |
| Evidence rule | Append-only once a release is accepted. Supersede, never edit. |

## Mandatory gates

Measured in this environment, on the commit above. A gate is PASS only if it was actually
run; nothing here is inferred from a related check passing.

| Gate | Pass bar | Result | Evidence |
|---|---|---|---|
| Source identity | Both locked SHAs resolve; 0 undocumented downstream delta | **PASS** | `01b6f83` is a direct ancestor of `5bc10d9`; upstream 271 commits ahead; **0** downstream-only commits |
| Evidence refs on origin | Named refs durable, not local-only | **PASS** (D-5) | `archive/snapshot-2026-08-01` and `hardening/openworker-security-baseline-2026-09-03` pushed |
| Patch ledger coverage | 100% of findings dispositioned | **PASS** | 18/18; 15/15 P0 with owner + disposition + test + prerequisite |
| Python reproducibility | `uv.lock` committed; `uv lock --check` clean; CI `--locked` | **PASS** | 111 packages; `ci.yml` and `release.yml` both resolve from the lock |
| JS reproducibility | `npm ci` from the committed lock | **PASS** | `npm ci` clean; lock committed |
| Rust reproducibility | Cargo locks preserved | **PASS** | `stt/Cargo.lock`, `surfaces/gui/src-tauri/Cargo.lock` tracked, unmodified |
| Spreadsheet parser | GHSA-4r6h-8v6p-xvw6 / GHSA-5pgg-2g8v-p4x9 absent from the active path | **PASS** | `xlsx` removed from `package.json` **and** `package-lock.json`; SBOM confirms absent |
| Backend tests | 100% pytest | **PASS** | **2354 passed, 1 skipped, 0 failed** |
| GUI unit + typecheck | 100% | **PASS** | **227 passed**; `npx tsc --noEmit` clean; `npm run build` OK |
| GUI E2E | 100% | **PASS** | **221 passed** |
| Rust | `cargo test` STT + Tauri `cargo check` | **PASS** | STT 4 passed; Tauri check clean |
| Approval corpus | 0 fail-open cases | **PASS** | 84 cases |
| Provenance + egress corpus | 0 escalation / unapproved new-destination cases | **PASS** | 52 cases |
| Network / MCP corpus | 0 private / link-local / unsafe-scheme cases | **PASS** | 54 cases |
| Files + shell corpus | 0 root escapes; 0 dangerous bare-command auto-runs | **PASS** | 76 cases |
| Audit + secrets corpus | 0 secret/body samples in persisted rows | **PASS** | 35 cases, asserted against the SQLite rows |
| Artifact isolation | Parent/token/IPC access impossible; CSP non-null; the gate gates | **PASS (shape)** | 7 CSP assertions + extended E2E probe + 3 component tests proving the capability gate blocks in BOTH positions |
| Durable state | Corrupt store cannot brick startup; atomic writes | **PASS** | 72 cases |
| Capability defaults | Nothing ON without a recorded authorization; pilot-locked capabilities OFF; both halves agree | **PASS** | 30 backend + 20 GUI assertions, including a cross-half agreement check |
| SCA — Python | 0 reachable High/Critical | **PASS** | `pip-audit --strict` over the exported lock: no vulnerabilities |
| SCA — npm | 0 reachable High/Critical | **PASS** | `npm audit --omit=dev`: **0 vulnerabilities** |
| SCA — Rust | 0 reachable High/Critical | **NOT RUN HERE** | `cargo audit` is wired into CI; not executed in this environment |
| Secret scanning | No new findings vs. the reviewed baseline | **PASS** | 97 known findings, all reviewed; negative control confirms the gate fails on a new one |
| SBOM | Generated per release | **PASS** | CycloneDX 1.6: 76 Python components, 407 npm components, plus both Cargo locks |
| CodeQL | Python / JS-TS / Actions / Rust | **NOT RUN HERE** | Wired into CI; requires the GitHub Actions runner |
| Dependency review | Blocks vulnerable additions in PRs | **NOT RUN HERE** | Wired into CI; PR-event only |
| Third-party CI actions pinned | Every `uses:` by commit SHA | **PASS** | 0 unpinned refs across both workflows |
| Internal macOS build | Built from a clean committed SHA | **BLOCKED** | No macOS host in this environment |
| Native secret round-trip | macOS Keychain get/put/delete | **BLOCKED** | `KeychainBackend` implemented; `security` CLI is macOS-only |
| Tauri CSP functional check | Policy behaves in the real webview | **BLOCKED** | Needs a desktop build; E2E runs against Vite in a plain browser |
| Rollback drill | Known-good restored <= 15 min | **BLOCKED** | Requires the built artifact |
| Restricted pilot | >= 7 days, >= 50 tasks, 0 critical incidents, >= 95% TTCR | **BLOCKED** | Wall-clock and operator-driven |
| Human GO | Explicit Mikkoh authorization | **NOT GIVEN** | — |

**Reachable P0 findings in enabled scope: 0.** Every P0 is either fixed with a regression
test, inherited from upstream with a corpus lock, not reproducible with evidence, or removed
from enabled scope by a capability that ships OFF.

## Capability gate matrix

Both halves of the table ship OFF and are verified by their own CI job
(`coworker/capabilities.py`, `surfaces/gui/src/capabilities.ts`).

| Capability | State | Prerequisite | Prerequisite met? | Authorized by | Authorized at |
|---|---|---|---|---|---|
| Local chat | ON | Backend + GUI unit green | Yes | Mikkoh Chen | 2026-11-23 |
| One granted workspace | ON | M06 corpus green | Yes | Mikkoh Chen | 2026-11-23 |
| Shell execution | ALWAYS ASK | M06 corpus green | Yes | — | — |
| Spreadsheet preview | **ON** (D-1) | M02 hostile-workbook corpus | MET | Mikkoh Chen | 2026-11-23 |
| Active HTML preview | **ON** (D-4) | M08 CSP + isolation corpus | PARTIAL — see the gap below | Mikkoh Chen | 2026-11-23 |
| Remote MCP | **OFF** (D-2) | M05 OAuth endpoint corpus | MET — locked OFF through the pilot | — | — |
| Connector writes | **OFF** (D-3) | M03 + M04 corpora | MET — locked OFF through the pilot | — | — |
| Scheduler / unattended | **OFF** | M03 + M04 + M07 | PARTIAL — M07 native secrets unverified | — | — |
| Browser automation | **OFF** | Per-hop **prevention** | **NOT MET** — the control is detection | — | — |
| High-sensitivity connectors | **OFF** | M07 redaction + native secret round-trip | PARTIAL — redaction met, round-trip blocked | — | — |

"Prerequisite MET" means the evidence exists. It does **not** by itself mean the capability
is on: enabling one is a decision for the change authority, recorded here against the check
that earned it. Claude Code has no authority to make it.

An enabled capability must carry an authorizer and a date, in both
`coworker/capabilities.py` and `surfaces/gui/src/capabilities.ts`. A bare `enabled=True`
without them fails the `capability-defaults` CI job, as does any disagreement between the
two halves of the table.

## Ratified decisions — 2026-11-23

| ID | Decision | Outcome | Consequence recorded |
|---|---|---|---|
| D-1 | Enable spreadsheet preview | **ENABLED** | Parser is bounded and advisory-free; legacy `.xls` is refused by magic-byte sniff rather than handed to a second binary parser |
| D-2 | Enable remote MCP | **STAYS OFF** | Prerequisite met; the strategy's launch checklist locks it through the restricted pilot |
| D-3 | Enable connector writes | **STAYS OFF** | Prerequisite met; same lock |
| D-4 | Active HTML preview left ON | **RATIFIED, gap disclosed** | Sandbox proven at browser level; the application CSP's **functional** behaviour is unverified because `tauri.conf.json` is applied by the Tauri webview and the E2E suite runs against Vite in a plain browser |
| D-5 | Push the archive and hardening refs to origin | **DONE** | `archive/snapshot-2026-08-01` → `01b6f83`, `hardening/openworker-security-baseline-2026-09-03` → `5bc10d9`, both on origin. They had been local-only and did **not** survive a container restart, which is the reason this mattered |
| D-6 | Accept `script-src 'unsafe-inline'` | **ACCEPTED** | Required by the pre-paint theme script and, decisively, by `srcdoc` CSP inheritance; the artifact frame remains opaque-origin with its own `default-src 'none'` |

The HTML preview gate is now **wired** (`RightRail.tsx` checks `activeHtmlPreview` before
rendering the frame), not merely declared. Before this, the table said OFF while the feature
was unconditionally ON — a flag that controls nothing reads as a control in review and
enforces nothing, which is worse than no flag.

## Environment limitations, stated plainly

This implementation environment is a Linux container. Four release inputs cannot be produced
here and are reported as BLOCKED rather than PASS:

| Input | Reason |
|---|---|
| `bash packaging/build_dmg.sh` | Requires macOS with the Xcode toolchain |
| Native macOS Keychain round-trip | Requires macOS Keychain Services / the `security` CLI |
| Tauri CSP functional behaviour | Requires the Tauri webview, not a browser |
| Rollback drill + 7-day / 50-task pilot | Require an installed build, wall-clock time, and the operator |

Two sandbox artifacts affected how the suites were run, and neither is a repository defect:

| Symptom | Cause | How evidence was produced |
|---|---|---|
| 7 pytest failures in `test_fake_slack.py` / `test_ui_refresh_e2e.py` | The container applies `HTTPS_PROXY` to **loopback** traffic; the relay answers 405 to plain HTTP | Re-run with the proxy variables cleared. These tests only talk to `127.0.0.1`, so nothing leaves the machine. All 7 pass. |
| Playwright cannot launch | The image ships Chromium 1194; this `@playwright/test` wants 1228, and there is no egress to fetch one | `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/pw-browsers/chromium` (opt-in config support added in M02) |

## Two gate defects found while ratifying, and fixed

Recorded because a gate that has never actually run is not evidence.

| Defect | Consequence had it shipped | Fix |
|---|---|---|
| The `secret-scan` job scanned `.secrets.baseline` itself, whose stored `hashed_secret` values trip the high-entropy detectors | The job would have reported all 97 accounted-for findings as brand new and failed on its **first** CI run — the classic permanently-red gate people learn to ignore | `.secrets.baseline` excluded from the scan; negative control re-verified (the gate still fails on a genuinely new secret) |
| Three browser-redirect cases in `tests/test_url_address_guard.py` resolved hostnames through the real DNS, unlike every sibling case in the file | Red on any runner with a restricted DNS view — and, worse, they would have passed for the **wrong reason** if a name stopped resolving, since the guard refuses what it cannot resolve | One file-wide autouse fixture resolves names to a fixed public address, with `localhost` deliberately left to the real resolver so the loopback-by-name assertion still means what it says. Every assertion unchanged; 44/44 |

The second one surfaced because this session's container was rebuilt mid-task and came back
with a narrower DNS view. That is the S6 health signal ("0 flaky mandatory security tests
across the last 10 runs") doing its job by accident, and it is why the M05 corpus was
written hermetic in the first place.

## Why no tag was created

`frictionless-v0.1.0+upstream.5bc10d9` requires an internal build, a rollback drill, a
>= 7-day / >= 50-task pilot at >= 95% Trusted Task Completion Rate, and an explicit human GO.
None of those exist. Creating the tag now would be a false completion marker, which the
implementation contract forbids outright.

## What a person must do next

1. Build on macOS from a clean committed SHA and record the artifact identity here.
2. Run the native Keychain round-trip and `SecretStore.migrate_to_backend()`; record
   `backend_name`. High-sensitivity connectors stay OFF until it reports `keychain`.
3. Verify the CSP functionally in the desktop build (app boots, sidecar connects, artifact
   preview still renders and stays sealed).
4. Run the rollback drill and record the elapsed time.
5. ~~Decide each capability whose prerequisite is MET.~~ **Done 2026-11-23** (D-1 … D-6).
   Revisit remote MCP and connector writes after the pilot.
6. Run the restricted pilot, then record the KPI and incident ledger here.
