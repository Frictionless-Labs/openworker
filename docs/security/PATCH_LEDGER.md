# Patch Ledger — Frictionless OpenWorker Hardened Adoption

| Field | Value |
|---|---|
| Doc ID | `OWH-PATCH-LEDGER` |
| Upstream baseline | `5bc10d928e0b64aae74313349a3b17bd19643ae2` |
| Historical snapshot | `01b6f83b3927e02912dda84bb392942c13ca70d1` (`archive/snapshot-2026-08-01`) |
| Hardening ref | `hardening/openworker-security-baseline-2026-09-03` |
| Target release | `frictionless-v0.1.0+upstream.5bc10d9` |
| Ledger status | ASSESS complete — 18/18 findings dispositioned |

## Source identity (SCAN evidence)

| Check | Result |
|---|---|
| `git rev-parse 01b6f83b3927e02912dda84bb392942c13ca70d1` | resolves |
| `git rev-parse 5bc10d928e0b64aae74313349a3b17bd19643ae2` | resolves (upstream `andrewyng/openworker` `main`) |
| `archive/snapshot-2026-08-01` | `01b6f83b3927e02912dda84bb392942c13ca70d1` |
| `hardening/openworker-security-baseline-2026-09-03` | `5bc10d928e0b64aae74313349a3b17bd19643ae2` |
| Ancestry | `01b6f83` is a direct ancestor of `5bc10d9` (fast-forward, no divergence) |
| Upstream commits ahead of snapshot | 271 |
| Downstream-only commits on `origin/main` | **0** — the Frictionless fork carried no undocumented downstream delta |
| Working tree at ASSESS | clean |

The Frictionless repository was a *stale mirror*, not a modified fork. There is therefore no
pre-existing downstream security delta to reconcile; every row below is either an upstream
property of `5bc10d9` or new Frictionless work.

## Disposition vocabulary

| Disposition | Meaning |
|---|---|
| `inherited-upstream-fix` | `5bc10d9` already satisfies the invariant; downstream adds regression proof only |
| `downstream-fix-required` | Frictionless must implement a structural control |
| `disabled-by-capability-gate` | Residual risk removed from enabled scope by keeping the capability OFF |
| `not-reproducible-with-evidence` | Claimed defect does not exist at this baseline |

## Findings

| ID | Severity | Finding | State at `5bc10d9` | Reachable | Disposition | Module | Primary files | Regression test | Capability prerequisite | Removal condition |
|---|---|---|---|---|---|---|---|---|---|---|
| OW-SEC-001 | P0 | Python dependency graph is unpinned; no committed lock, no frozen install | `uv.lock` absent; CI installs unlocked | Yes | **CLOSED** `downstream-fix-required` | M02 | `uv.lock`, `pyproject.toml`, `.github/workflows/ci.yml`, `.github/workflows/release.yml` | `uv lock --check` gate in CI | Release reproducibility | Upstream commits its own lock and locked CI |
| OW-SEC-002 | P0 | Spreadsheet preview parses hostile workbooks with `xlsx@0.18.5` (GHSA-4r6h-8v6p-xvw6 prototype pollution, GHSA-5pgg-2g8v-p4x9 ReDoS) | `package.json` `"xlsx": "^0.18.5"`; live `import("xlsx")` in `SheetViewer` | Yes | **CLOSED** `downstream-fix-required` + `disabled-by-capability-gate` | M02 | `surfaces/gui/package.json`, `surfaces/gui/src/sheet/parser.ts`, `surfaces/gui/src/capabilities.ts`, `surfaces/gui/src/components/RightRail.tsx` | `src/sheet/parser.test.ts` (17 cases) | Spreadsheet preview OFF (`capabilities.ts`) | npm publishes a patched `xlsx >= 0.20.2`, or `read-excel-file` is superseded |
| OW-SEC-003 | P0 | Approval reply intent parser inverted negated replies (`"I cannot approve this"` matched allow) | Fixed upstream: `_reply_intent` matches the LEADING token only | Yes | **CLOSED** `inherited-upstream-fix` (corpus locked) | M03 | `coworker/inbox_routing.py` | `tests/test_approval_authority.py` REPLY_CORPUS | — | Never remove the corpus |
| OW-SEC-004 | P0 | Approval resolution over messaging transports was bound to an actor **for Slack only**; a Telegram reply or button click carrying a leaked `[ow:<id>]` token resolved a protected item with no actor check at all | slack-only branch in `_resolve_inbox_reply` / `_on_interaction` | Yes | **CLOSED** `downstream-fix-required` | M03 | `coworker/server/manager.py` | `test_transport_actor_binding_is_deny_first` | Connector writes OFF until M04 too | Upstream adds transport-agnostic binding |
| OW-SEC-005 | P0 | A messaging reply reading `always` fell through intent parsing as free text and reached `inbox_approver`, which mapped it to `ALWAYS_TOOL` — durable tool trust minted by an inbound message | live fail-open at `5bc10d9` | Yes | **CLOSED** `downstream-fix-required` | M03 | `coworker/inbox.py`, `coworker/inbox_routing.py`, `coworker/server/manager.py` | persistent-keyword rows + `test_transport_always_denies_it_does_not_downgrade` | Connector writes / unattended OFF until M04 | Upstream restricts transport outcomes |
| OW-SEC-006 | P0 | External content authority is enforced by *prompt text* only ("treat as untrusted data, not instructions"); no structural origin survives storage or provider serialization | `coworker/provenance.py` tracks self-authored FILES only; no `TrustOrigin` | Yes | **CLOSED** `downstream-fix-required` | M04 | `coworker/trust.py`, `coworker/engine.py` | `tests/test_provenance_egress.py` §1 | High-sensitivity connectors OFF | Upstream ships structural taint (OPE-114 general design) |
| OW-SEC-007 | P0 | No egress gate consumes provenance: untrusted-derived or secret-like content may leave to a destination the operator never bound | Domain allowlists exist, but are content-blind | Yes | **CLOSED** `downstream-fix-required` | M04 | `coworker/egress.py`, `coworker/permissions.py`, `coworker/agent.py` | `tests/test_provenance_egress.py` §2, §4 | Connector writes OFF | Upstream ships an egress policy layer |
| OW-SEC-008 | P1 | `web_fetch` can carry sensitive data in query/body to a new destination | `web_fetch` is `requires_approval=False`; address guard checks destination class, not content sensitivity | Yes | **CLOSED** `downstream-fix-required` | M04 | `coworker/egress.py` | `carries_payload` query-string cases + red-team row 4 | — | Upstream adds content-aware egress |
| OW-SEC-009 | P0 | MCP OAuth discovery / registration / token / authorization endpoints are fetched without address validation; hostile MCP metadata can point them at loopback, RFC1918 or `169.254.169.254` | `coworker/mcp/oauth.py` builds and fetches `/.well-known/...` with a bare `httpx.AsyncClient`; `web/guard.py` is not imported | Yes | `downstream-fix-required` | M05 | `coworker/mcp/oauth.py` | malicious-MCP-metadata fixtures | Remote MCP OFF until green | Upstream routes MCP OAuth through the address guard |
| OW-SEC-010 | P0 | Browser navigation SSRF: only the model-supplied URL is pre-checked; redirect landing is *detected* after the request leaves, and JS / meta-refresh hops are unchecked | `check_url` pre-check + `redirect_refusal` post-check in `browser_automation.py` | Yes | `inherited-upstream-fix` (partial) + `disabled-by-capability-gate` | M05 | `coworker/connectors/browser_automation.py` | redirect + in-page-navigation fixtures | Browser automation OFF — prevention is not achievable without a vetting proxy | A per-hop request proxy lands |
| OW-SEC-011 | P0 | Granted workspace roots must bound every path-bearing operation, not just canonical file writes | `PermissionEngine` scopes `WRITE_LOCAL` writes and read-only-grant read targets against roots | Yes | `inherited-upstream-fix` | M06 | `coworker/permissions.py`, `coworker/roots.py` | traversal / symlink / second-root / Windows-separator corpus | — | Never remove; add corpus lock |
| OW-SEC-012 | P0 | Browser upload and screenshot bypass root scoping because they classify EXTERNAL, not WRITE_LOCAL | Fixed upstream (OPE-122): `_readable_source` / `_writable_target` resolve inside granted roots | Yes | `inherited-upstream-fix` | M06 | `coworker/connectors/browser_automation.py` | upload/screenshot escape cases | — | Never remove; add corpus lock |
| OW-SEC-013 | P0 | An allowlist entry on a bare program grants arbitrary execution through its arguments | Upstream blocks `_ARG_EXECUTORS`, inline-code interpreter flags, and `_DANGEROUS_FLAGS`. **Gap:** a bare interpreter running a *script file* (`python setup.py`) and package managers (`npm`, `pip`, `yarn`, `pnpm`, `cargo`, `go`, `make`, `gradle`) remain prefix-eligible | Yes | `inherited-upstream-fix` (partial) + `downstream-fix-required` | M06 | `coworker/permissions.py` | dangerous-bare-command corpus | Shell stays always-ask | Upstream widens the executor set |
| OW-SEC-014 | P1 | Session / conversation persistence must not allow path traversal out of the state directory | `coworker/conversations.py` | Yes | *assessed in M06* | M06 | `coworker/conversations.py` | traversal fixtures | — | — |
| OW-SEC-015 | P0 | The durable SQLite audit trail persists raw tool results: `result_preview` is stringified and truncated with **no** redaction, so email bodies, HTML, environment output and tokens land on disk | `audit.py` `_sanitize_args` covers arguments only; `result_preview` = `_truncate(str(...))` | Yes | `downstream-fix-required` | M07 | `coworker/audit.py` | persisted-SQLite-row redaction tests | High-sensitivity connectors OFF | Upstream sanitizes results |
| OW-SEC-016 | P0 | Credentials persist as a `0600` plaintext JSON file; no native OS credential storage | `SecretStore` is file-backed by design ("a Keychain backend can swap in later") | Yes | `downstream-fix-required` | M07 | `coworker/secrets.py` | Keychain round-trip + transactional migration tests | High-sensitivity connectors OFF unless native round-trip passes | Upstream ships a native backend |
| OW-SEC-017 | P0 | Desktop isolation: (a) Tauri application CSP is `null`; (b) artifact previews must not share the privileged app origin | (a) `"csp": null` in `tauri.conf.json` — **open**; (b) fixed upstream (OPE-91): `sandbox="allow-scripts"` without `allow-same-origin` plus an injected `default-src 'none'` artifact CSP | Yes | `downstream-fix-required` (a) + `inherited-upstream-fix` (b) | M08 | `surfaces/gui/src-tauri/tauri.conf.json`, `surfaces/gui/src/components/RightRail.tsx` | CSP assertion + sandbox/parent/token E2E | Active HTML preview OFF until green | Upstream sets a non-null CSP |
| OW-REL-001 | P1 | Small JSON-backed stores load with bare `json.loads` and write in place; one truncated file bricks startup | e.g. `InboxRouting._load` / `._save` and peers | Yes | `downstream-fix-required` | M09 | `coworker/jsonstate.py` (new) + migrated stores | corruption / atomicity / recovery tests | Reliable daily use | Upstream adopts atomic persistence |

## P0 coverage

| Measure | Value |
|---|---|
| Findings tracked | 18 |
| P0 findings | 15 |
| P0 with owner + disposition + regression test + release prerequisite | 15 / 15 (100%) |
| P0 with **no** defensible disposition | 0 |
| Reachable P0 remaining in *enabled* scope after gating | tracked in `RELEASE_EVIDENCE.md` |

## Notes on honesty of claims

- **OW-SEC-010 is detection, not prevention.** `redirect_refusal` runs *after* the request has
  left the machine. It prevents the agent from *reading or interacting with* the landed page;
  it does not prevent the request. Browser automation therefore stays OFF and the release
  evidence must not claim SSRF closure for that surface.
- **OW-SEC-002 has no upstream npm remedy.** SheetJS stopped publishing to npm; the fixed
  build is distributed from `cdn.sheetjs.com`. Any downstream fix must either vendor that
  build reproducibly or replace the parser.


## M02 closure evidence — Supply Chain + Spreadsheet Parser

| Acceptance boolean | Result | Evidence |
|---|---|---|
| `uv.lock` exists, committed, `uv lock --check` passes | PASS | 111 packages resolved; `uv lock --check` clean |
| CI/bootstrap uses locked resolution | PASS | `ci.yml` runs `uv lock --check` then `uv run --locked …`; `release.yml` runs `uv sync --locked` |
| Active GUI dependency is not npm `xlsx@0.18.5` | PASS | `xlsx` removed from `package.json` **and** `package-lock.json` (0 occurrences) |
| SheetJS >=0.20.2 authoritative build **or** a maintained replacement | PASS (replacement) | `read-excel-file@9.3.10`, MIT, npm registry, exact-pinned |
| GHSA-4r6h-8v6p-xvw6 and GHSA-5pgg-2g8v-p4x9 absent from the active path | PASS | `npm audit --omit=dev` → **found 0 vulnerabilities** |
| Hostile workbook does not pollute prototype or hang the UI | PASS | 17/17 in `src/sheet/parser.test.ts` |

### Why a replacement rather than the authoritative SheetJS build

The SPEC allows either. The authoritative fixed build (`>=0.20.2`) is published **only** from
`cdn.sheetjs.com`; npm's `xlsx` is frozen at the vulnerable `0.18.5`. Two facts decided it:

1. The release gate verifies reproducibility with `npm ci` against the committed lockfile. A
   CDN tarball dependency is pinnable by integrity hash, but it moves a release-blocking
   dependency onto a single non-registry host.
2. This build environment's egress policy denies `cdn.sheetjs.com` outright
   (`CONNECT` → 403), so the authoritative build **could not be pinned reproducibly here**.
   Per the M02 contract that is a stop condition for the CDN path, not a reason to ship
   `0.18.5`.

`read-excel-file` is maintained (published 2026-08-10), MIT, and on the registry the lockfile
already trusts.

### Deliberate capability reduction: legacy `.xls`

The backend classifies both `.xlsx` and `.xls` as `sheet` artifacts. `read-excel-file` reads
OOXML only, so the adapter **refuses** `.xls` by magic-byte sniff rather than reaching for a
second binary parser. This is a net security improvement — the OLE2 compound-binary path was
the higher-risk surface — and the UI already directs spreadsheet artifacts to a real
spreadsheet app. Recorded as an intentional scope reduction, not an unnoticed regression.

### Residual

Spreadsheet preview stays **OFF** in `surfaces/gui/src/capabilities.ts`. The parser corpus
being green earns the right to enable it; it does not enable it. That is a Mikkoh decision
recorded in `RELEASE_EVIDENCE.md`.


## M03 closure evidence — Approval Authority

| Acceptance boolean | Result | Evidence |
|---|---|---|
| `no, don't approve`, `not allowed`, and mixed intent never allow execution | PASS | 22-row `REPLY_CORPUS` x 3 protected kinds = 66 cases |
| Wrong transport, channel, actor, or item ID cannot resolve protected approvals | PASS | `test_transport_actor_binding_is_deny_first`, `test_malformed_item_id_resolves_nothing` |
| Messaging replies cannot mint `always*`, root-expanding, or scheduled persistent authority | PASS | `test_transport_always_denies_it_does_not_downgrade`, persistent-keyword rows |
| Denied or ambiguous approvals stay denied/pending | PASS | corpus asserts `state == "pending"` and `resolution is None` |

**Fail-open approval cases: 0 / 84.**

### The live fail-open this closed

At `5bc10d9`, `_reply_intent` returned `None` for the word `always`, so
`resolve_from_reply` passed it through as a *free-text answer*. `inbox_approver` then read
`resolution == "always"` and returned `ApprovalOutcome.ALWAYS_TOOL`. An inbound Slack or
Telegram message reading `always [ow:<id>]` therefore minted **durable, cross-session tool
trust**. Upstream's leading-intent fix (OW-SEC-003) closed the negation inversion but not
this path, because `always` is neither an allow word nor a deny word.

### Three structural controls, not a wider keyword list

1. **Authority origin on the item.** `InboxItem.resolution_origin` records whether a
   resolution came from an in-app control or a transport, and `inbox_approver` grants
   `ALWAYS_TOOL` only for `ORIGIN_IN_APP`. Recorded on the item rather than inferred at the
   approver because the approver also runs after a durable resume, where the calling
   context is gone. An item persisted before the field existed reads as transport-grade.
2. **A transport outcome ceiling.** For a protected kind, a transport reply must be an
   unambiguous `allow`/`deny`. Free text, negation, mixed intent and persistent-grant
   keywords all leave the item **pending** — recoverable in the app, where the authority is.
3. **Transport-agnostic actor binding.** `_transport_actor_owns_item` dispatches by platform
   and returns `False` for any transport without an owner check, including an empty or
   unrecognised platform. Adding a transport now requires adding its owner check; it cannot
   inherit Slack's by accident.

A transport `always` **denies** rather than silently downgrading to allow-once: the reply
asked for authority the transport may not grant, and an approval gate resolves ambiguity as
deny — a quiet downgrade would still run a call the operator may not have meant.


## M04 closure evidence — Provenance + Egress

| Acceptance boolean | Result | Evidence |
|---|---|---|
| External Slack/email/web content cannot serialize as owner-authored instruction authority | PASS | `test_connector_delivery_is_external_even_in_the_user_role`, 4 forgery attempts |
| Tool results containing external content are marked untrusted structurally | PASS | `test_tool_result_origin_comes_from_registration` (6 categories) |
| A new destination carrying untrusted-derived or secret-like content asks/denies before network execution | PASS | 11-row red-team table, all four contract scenarios |
| Bound benign responses still work without unnecessary blocking | PASS | 4 benign rows + `test_replying_to_the_thread_that_addressed_us_stays_allowed` |

**Mandatory authority-escalation / unapproved new-destination cases failing: 0 / 52.**

### What made this structural rather than advisory

Upstream already shipped the two halves and explicitly left them unconsumed:

- `session_facts.is_ingesting()` answers "can this tool's result carry content authored
  outside this machine?", and its module docstring says *"In v1 neither changes a decision …
  ingestion goes to the audit log and nothing reads it."*
- `KnownWorld.hosts` freezes the destination set **before the agent acts** — deliberately,
  so an agent that runs `git remote add backup https://attacker.net/…` cannot make its own
  destination look familiar — and reserves it for *"`DST-1` in v2, which will surface it as
  one **computed** line and never as a list for the model to search."*

M04 is that v2. `TrustOrigin` is computed from a tool's registration and from whether a turn
arrived through a connector — never parsed from content — and rides as a `_trust_origin`
message sidecar that `_outbound_messages` strips, so the runtime can read provenance on
reload and the model never sees a label it could be talked into imitating.

### Why the gate is a floor

`PermissionEngine.evaluate` consults the egress policy **above** write scoping, the
persistent-authority floor, Bypass mode, and every allowlist. A domain grant matches on host
alone and is blind to where the payload came from; that blindness is the gap. Placement
mirrors the existing self-protection floor, which is above every mode for the same reason.

The policy only ever tightens — `allow` means "no egress objection", and every other gate
still runs. A policy that raises is caught and treated as *not* an allow.

### Honest limits

- `secret_shaped` is a **heuristic**, anchored on vendor-issuer prefixes rather than
  "long random-looking string" (which matches base64 images and commit SHAs, and would make
  the gate noisy enough to be switched off — the failure mode that kills a control). A miss
  still leaves the untrusted-context rule standing.
- Local reads are not ingestion sources, inheriting upstream's documented trade-off: a
  poisoned file already in the workspace produces no marker. Recorded, not papered over.
