# Implementation Status

Read this file first in any resumed session, after `CLAUDE.md`, `SPEC.md`, and `docs/RUNBOOK.md`.

| Field | Value |
|---|---|
| Baseline | `5bc10d928e0b64aae74313349a3b17bd19643ae2` on `claude/openworker-hardened-adoption-m7iwq6` |
| Phase | GUIDE |
| Module | M01 Baseline + Patch Ledger — **PASS** |
| Changed files | `CLAUDE.md`, `SPEC.md`, `docs/RUNBOOK.md`, `docs/security/PATCH_LEDGER.md`, `docs/security/RELEASE_EVIDENCE.md`, `docs/security/IMPLEMENTATION_STATUS.md` |
| Tests | `uv run --locked pytest tests -q` baseline captured; `(cd surfaces/gui && npm test)` = 181/181 PASS |
| Findings | OW-SEC-001..017 and OW-REL-001 opened and dispositioned (18/18) |
| Decisions | None required from Mikkoh yet |
| Next step | Implement M02 Supply Chain + Spreadsheet Parser |

## M01 acceptance booleans

- [x] Historical snapshot ref resolves to `01b6f83b3927e02912dda84bb392942c13ca70d1`
- [x] Hardening base resolves to `5bc10d928e0b64aae74313349a3b17bd19643ae2`
- [x] Every downstream patch row has a finding ID, tests, upstream status, and removal condition
- [x] No undocumented downstream security delta (0 downstream-only commits)

## Module ledger

| Module | State |
|---|---|
| M01 Baseline + Patch Ledger | PASS |
| M02 Supply Chain + Spreadsheet Parser | NOT STARTED |
| M03 Approval Authority | NOT STARTED |
| M04 Provenance + Egress | NOT STARTED |
| M05 MCP + Browser Network Guard | NOT STARTED |
| M06 Files + Shell Confinement | NOT STARTED |
| M07 Audit + Secrets | NOT STARTED |
| M08 Artifact Isolation + CSP | NOT STARTED |
| M09 Durable State | NOT STARTED |
| M10 CI + Release Gate | NOT STARTED |
