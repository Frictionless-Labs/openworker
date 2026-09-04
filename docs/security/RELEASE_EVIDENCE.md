# Release Evidence — `frictionless-v0.1.0+upstream.5bc10d9`

| Field | Value |
|---|---|
| Source SHA | *pending — set at release candidate cut* |
| Upstream baseline | `5bc10d928e0b64aae74313349a3b17bd19643ae2` |
| Historical snapshot | `01b6f83b3927e02912dda84bb392942c13ca70d1` |
| Release status | **NOT RELEASABLE** — gates open |
| Evidence rule | Append-only once a release is accepted. Supersede, never edit. |

## Mandatory gates

| Gate | Pass bar | Status | Evidence |
|---|---|---|---|
| Source identity | Both locked SHAs resolve; 0 undocumented downstream delta | PASS | `PATCH_LEDGER.md` SCAN table |
| Patch ledger coverage | 100% of findings dispositioned | PASS | 18/18 |
| Python reproducibility | `uv.lock` committed; `uv lock --check` clean; CI `--locked` | *pending M02* | |
| JS reproducibility | `npm ci` from committed lock | *pending M02* | |
| Rust reproducibility | Cargo locks preserved | *pending M02* | |
| Spreadsheet parser | GHSA-4r6h-8v6p-xvw6 / GHSA-5pgg-2g8v-p4x9 absent from active path | *pending M02* | |
| Approval corpus | 0 fail-open cases | *pending M03* | |
| Provenance + egress corpus | 0 authority-escalation / unapproved new-destination cases | *pending M04* | |
| Network / MCP corpus | 0 private / link-local / unsafe-scheme cases | *pending M05* | |
| Files + shell corpus | 0 root escapes; 0 dangerous bare-command auto-runs | *pending M06* | |
| Audit + secrets | 0 secret/body samples in persisted rows; native secret round-trip | *pending M07* | |
| Artifact isolation + CSP | Parent/token access impossible; CSP non-null | *pending M08* | |
| Durable state | Corrupt store cannot brick startup; atomic writes | *pending M09* | |
| Backend tests | 100% pytest | *pending* | |
| GUI unit tests | 100% | *pending* | |
| GUI E2E | 100% | *pending* | |
| Rust | `cargo test` STT + Tauri `cargo check` | *pending* | |
| CodeQL | Python / JS-TS / Rust where supported | *pending M10* | |
| Dependency review | Blocks vulnerable additions in PRs | *pending M10* | |
| SCA (Python / npm / Rust) | 0 reachable High/Critical release blockers | *pending M10* | |
| Secret scanning | Clean | *pending M10* | |
| SBOM | Generated per release | *pending M10* | |
| Capability defaults | Risky capabilities OFF | *pending M10* | |
| Internal macOS build | Built from a clean committed SHA | **BLOCKED** — no macOS host in this environment |
| Rollback drill | Known-good restored <= 15 min | **BLOCKED** — requires the built artifact |
| Restricted pilot | >= 7 days, >= 50 tasks, 0 critical incidents, >= 95% TTCR | **BLOCKED** — wall-clock and operator-driven |
| Human GO | Explicit Mikkoh authorization | **NOT GIVEN** |

## Capability gate matrix

| Capability | Default | Prerequisite gates | Enabled by | Enabled at |
|---|---|---|---|---|
| Local chat | ON after core suite | Backend + GUI unit green | — | — |
| One granted workspace | ON after core suite | M06 corpus green | — | — |
| Shell execution | ALWAYS ASK | M06 corpus green | — | — |
| Remote MCP | OFF | M05 corpus green (OW-SEC-009) | — | — |
| Connector writes | OFF | M03 + M04 corpora green | — | — |
| Scheduler / unattended | OFF | M03 + M04 + M07 green | — | — |
| Active HTML preview | OFF | M08 green (OW-SEC-017a) | — | — |
| Spreadsheet preview | OFF | M02 green (OW-SEC-002) | — | — |
| Browser automation | OFF | OW-SEC-010 prevention (not detection) | — | — |
| High-sensitivity connectors | OFF | M07 audit redaction + native secret round-trip | — | — |

## Environment limitations recorded honestly

This implementation environment is a Linux container. The following release inputs
**cannot be produced here** and are reported as BLOCKED rather than PASS:

| Input | Reason |
|---|---|
| `bash packaging/build_dmg.sh` | Requires macOS with Xcode toolchain |
| Native macOS Keychain round-trip | Requires macOS `security` / Keychain services |
| Rollback drill timing | Requires an installed desktop build |
| 7-day / 50-task restricted pilot | Requires wall-clock time and operator task execution |

No gate above is marked PASS on the basis of an unrun check.
