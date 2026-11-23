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
| OW-SEC-009 | P0 | MCP OAuth discovery / registration / token / authorization endpoints are fetched without address validation; hostile MCP metadata can point them at loopback, RFC1918 or `169.254.169.254` | `coworker/mcp/oauth.py` builds and fetches `/.well-known/...` with a bare `httpx.AsyncClient`; `web/guard.py` is not imported | Yes | **CLOSED** `downstream-fix-required` | M05 | `coworker/mcp/oauth.py`, `coworker/web/guard.py`, `coworker/capabilities.py`, `coworker/mcp/client.py` | `tests/test_mcp_network_guard.py` | Remote MCP still OFF (gate at the transport) | Upstream routes MCP OAuth through the address guard |
| OW-SEC-010 | P0 | Browser navigation SSRF: only the model-supplied URL is pre-checked; redirect landing is *detected* after the request leaves, and JS / meta-refresh hops are unchecked | `check_url` pre-check + `redirect_refusal` post-check in `browser_automation.py` | Yes | **ACCEPTED-AS-GATED** `inherited-upstream-fix` (partial) + `disabled-by-capability-gate` | M05 | `coworker/connectors/browser_automation.py`, `coworker/capabilities.py` | `tests/test_mcp_network_guard.py` browser section | Browser automation OFF — detection, not prevention | A per-hop request proxy lands |
| OW-SEC-011 | P0 | Granted workspace roots must bound every path-bearing operation, not just canonical file writes | `PermissionEngine` scopes `WRITE_LOCAL` writes and read-only-grant read targets against roots | Yes | **CLOSED** `inherited-upstream-fix` + downstream shell-path scoping | M06 | `coworker/permissions.py` | `tests/test_files_shell_confinement.py` §1, §2, §5 | — | Never remove the corpus |
| OW-SEC-012 | P0 | Browser upload and screenshot bypass root scoping because they classify EXTERNAL, not WRITE_LOCAL | Fixed upstream (OPE-122): `_readable_source` / `_writable_target` resolve inside granted roots | Yes | **CLOSED** `inherited-upstream-fix` (corpus locked) | M06 | `coworker/connectors/browser_automation.py` | `tests/test_files_shell_confinement.py` §4 | — | Never remove the corpus |
| OW-SEC-013 | P0 | An allowlist entry on a bare program grants arbitrary execution through its arguments | Upstream blocks `_ARG_EXECUTORS`, inline-code interpreter flags, and `_DANGEROUS_FLAGS`. **Gap:** a bare interpreter running a *script file* (`python setup.py`) and package managers (`npm`, `pip`, `yarn`, `pnpm`, `cargo`, `go`, `make`, `gradle`) remain prefix-eligible | Yes | **CLOSED** `inherited-upstream-fix` (partial) + `downstream-fix-required` | M06 | `coworker/permissions.py`, `tests/test_command_matching.py` | `tests/test_files_shell_confinement.py` §3 (22 dangerous + 5 benign) | Shell stays always-ask | Upstream widens the executor set |
| OW-SEC-014 | P1 | Session / conversation persistence must not allow path traversal out of the state directory | `coworker/conversations.py` | Yes | **CLOSED** `not-reproducible-with-evidence` | M06 | `coworker/conversations.py` (unchanged) | `tests/test_files_shell_confinement.py` §6 | — | Never remove the corpus |
| OW-SEC-015 | P0 | The durable SQLite audit trail persists raw tool results: `result_preview` is stringified and truncated with **no** redaction, so email bodies, HTML, environment output and tokens land on disk | `audit.py` `_sanitize_args` covers arguments only; `result_preview` = `_truncate(str(...))` | Yes | **CLOSED** `downstream-fix-required` | M07 | `coworker/audit.py` | `tests/test_audit_secrets.py` §1-2 (reads the persisted rows) | High-sensitivity connectors OFF | Upstream sanitizes results |
| OW-SEC-016 | P0 | Credentials persist as a `0600` plaintext JSON file; no native OS credential storage | `SecretStore` is file-backed by design ("a Keychain backend can swap in later") | Yes | **PARTIAL — gated** `downstream-fix-required` | M07 | `coworker/secrets.py` | `tests/test_audit_secrets.py` §3 (migration logic proven; macOS round-trip UNVERIFIED here) | High-sensitivity connectors OFF — the native round-trip has not been run on the launch platform | Upstream ships a native backend |
| OW-SEC-017 | P0 | Desktop isolation: (a) Tauri application CSP is `null`; (b) artifact previews must not share the privileged app origin | (a) `"csp": null` in `tauri.conf.json` — **open**; (b) fixed upstream (OPE-91): `sandbox="allow-scripts"` without `allow-same-origin` plus an injected `default-src 'none'` artifact CSP | Yes | **CLOSED (shape) / gated (functional)** | M08 | `surfaces/gui/src-tauri/tauri.conf.json`, `surfaces/gui/src/csp.test.ts`, `surfaces/gui/e2e/{artifacts.spec.ts,fixtures.ts}` | 7 CSP shape assertions + extended sandbox/parent/token/IPC E2E | CSP functional check needs a macOS Tauri build — BLOCKED here | Upstream sets a non-null CSP |
| OW-REL-001 | P1 | Small JSON-backed stores load with bare `json.loads` and write in place; one truncated file bricks startup | e.g. `InboxRouting._load` / `._save` and peers | Yes | **CLOSED** `downstream-fix-required` | M09 | `coworker/jsonstate.py`, `coworker/{inbox,inbox_routing,mentions,unrouted,unattended,overrides}.py` | `tests/test_durable_state.py` (72 cases) | Reliable daily use | Upstream adopts atomic persistence |

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


## M05 closure evidence — MCP + Browser Network Guard

| Acceptance boolean | Result | Evidence |
|---|---|---|
| MCP discovery / authorization / registration / token endpoints require acceptable schemes and public destinations | PASS | 21 blocked-endpoint rows; 6 hostile-metadata documents |
| Browser public→private redirects blocked before content becomes readable | PASS (detection) | 4 redirect rows; see the honesty note below |
| Loopback, RFC1918, link-local, cloud metadata, unsafe schemes fail mandatory tests | PASS | includes IPv6 loopback, IPv4-mapped loopback, CGNAT, multicast, reserved |
| Legitimate public HTTPS MCP OAuth still completes | PASS | `test_legitimate_public_https_endpoint_is_allowed`, `test_auth_flow_passes_a_clean_request_through` |

**Mandatory private / link-local / unsafe-scheme cases failing: 0 / 54.**

### One chokepoint, not four patches

Upstream already had a mature address guard (`coworker/web/guard.py`: loopback, RFC1918,
link-local, CGNAT, multicast, reserved, IPv4-mapped, per-hop redirect walking, and
connection pinning that closes the DNS-rebinding window). It was wired into `web_fetch`,
`integration_tools` and `browser_automation` — and **not** into `coworker/mcp/oauth.py`,
which fetched `/.well-known/...` with a bare `httpx.AsyncClient` and then followed whatever
endpoints the returned metadata named.

The guard is now applied at `async_auth_flow`, the generator through which the MCP SDK
routes discovery, dynamic client registration, the code exchange and every silent refresh.
Vetting each request it yields covers server-supplied endpoints without reimplementing the
SDK's flow or tracking its internals version by version. Three narrower doors are guarded
too: the module's own well-known fetch, the authorization URL handed to the *system*
browser, and the configured server URL.

`check_endpoint` adds one rule to `check_url`: **https only**. Plain HTTP is fine for
`web_fetch` and never fine for a token exchange.

### Construction vs. point of use

`build_auth` validates `scheme_only` — scheme and any literal IP, but no DNS. Resolving a
NAME at construction would let a transient DNS failure become a hard construction failure
while buying nothing, because every request is vetted again at the point it actually leaves.
Point-of-use recheck is the rule that matters; a construction-time resolve is a weaker copy
of it.

### OW-SEC-010 is DETECTION, and the evidence says so

`redirect_refusal` runs **after** the request has left the machine. It stops the agent
reading or interacting with the landed page; it does not stop the request, and later
JavaScript- or meta-refresh-driven navigation is unchecked. Closing that needs a proxy that
vets every hop. Until then `browser_automation` is OFF, and no release evidence may claim
SSRF closure for that surface.

## M06 closure evidence — Files + Shell Confinement

| Acceptance boolean | Result | Evidence |
|---|---|---|
| File, browser upload/screenshot, attachment, and shell path access cannot escape granted roots | PASS | 6 shell-escape rows, 5 browser rows, 3 write-escape rows |
| Interpreters, package managers and exec wrappers never gain arbitrary authority from a bare allowlist entry | PASS | 22 dangerous-command rows |
| Symlink and Windows path cases pass | PASS | `test_a_symlink_pointing_out_of_the_root_does_not_escape`, backslash-traversal rows |
| In-root benign operations remain usable | PASS | 4 benign shell rows, 5 specific-rule rows, second-root row |

**Path escapes: 0. Dangerous bare-command automatic executions: 0. (76 cases.)**

### The two real gaps

Upstream's engine was already strong — `_ARG_EXECUTORS`, inline-code interpreter flags,
`find -exec`/`-delete`, protected settings paths, write scoping, and root checks on the
read-only session grant. Two holes remained:

1. **An allowlist entry vetted what a command did, not what it touched.** `cat` on the
   allowlist auto-read `~/.aws/credentials` and any other repository's history. The
   self-protection floor does not catch it — that floor guards a fixed set of settings
   files, not the granted roots. Root scoping now applies to an allowlisted command's path
   operands, and an out-of-root path falls through to **approval** rather than denying, so
   the operator can still say yes once.
2. **A bare delegating program was not a decision about anything.** `python` covered
   `python attacker.py`; `npm` covered `npm install <anything>`. `python -c` and
   `python evil.py` differ only in where the code is stored. A rule that names a
   subcommand or script still auto-runs — a gate people route around is not a gate.

`_path_operands` unions a POSIX **and** a non-POSIX `shlex` parse: POSIX mode is how the
command really splits on macOS/Linux but eats backslashes, so `..\..\etc\passwd` arrives
as `....etcpasswd` with no separator left to notice.

### One upstream test was tightened, not weakened

`test_interpreter_without_inline_code_is_still_eligible` asserted that a bare `python` rule
covers `python script.py` — the exact behaviour OW-SEC-013 exists to remove. It is replaced
by `test_a_bare_interpreter_entry_does_not_cover_a_script`, which asserts the stricter
contract **and** that a rule naming the script still works.

### OW-SEC-014 was not reproducible

`ConversationStore._file` already rejects any id that is not a safe path component and
re-confirms the resolved parent. 15 crafted ids are now locked in.

## M07 closure evidence — Audit + Secrets

| Acceptance boolean | Result | Evidence |
|---|---|---|
| Email bodies, environment secret values, access tokens, API keys and HTML do not persist in audit previews | PASS | 18 sensitive payloads, each asserted against the **persisted SQLite row** |
| Audit rows still identify tool, stage, resource, approval origin and call ID | PASS | `test_the_row_still_identifies_the_action`, `test_structure_survives_redaction` |
| macOS secret backend uses native storage for the launch platform | **IMPLEMENTED, UNVERIFIED** | `KeychainBackend` shells out to macOS `security`; it cannot be exercised on this Linux host |
| Migration rollback does not destroy the only credential copy | PASS | write → **read-back verify** → retire by *rename*; 3 failure-path tests |

**Secret / body samples in persisted rows: 0 / 18.**

### Truncation is not redaction

The baseline persisted `_truncate(str(result))`. A 500-character prefix of an email body is
still an email body, and a token shorter than the limit survives truncation whole. Redaction
now runs on the **structured** result, before flattening — and the corpus asserts against the
row read back out of SQLite, because a sanitizer that ran on the way to the UI and not on
the way to disk would pass an in-memory test and still leave the bytes on the disk.

### The migration ordering IS the control

Write, verify by reading back, and only then retire the legacy file — by **rename**, never
by delete. At no point does exactly one copy of a credential exist. Any failure raises
`MigrationError` with the legacy file untouched, so the rollback is "do nothing".

### Honest limit

`KeychainBackend.available()` returns False off macOS, so this build runs on the file
backend and `SecretStore.backend_name` reports `"file"`. **The native round-trip named in
the M07 acceptance criteria has not been executed.** `high_sensitivity_connectors` therefore
stays OFF, which is the documented consequence rather than an oversight.

## M08 closure evidence — Artifact Isolation + CSP

| Acceptance boolean | Result | Evidence |
|---|---|---|
| HTML preview cannot access `parent.document` or the OpenWorker API token | PASS | E2E probe: parent blocked, token blocked, IPC blocked, own storage denied |
| HTML preview cannot exfiltrate through unrestricted subresources | PASS | E2E probe: network blocked (upstream's injected `default-src 'none'`) |
| Tauri CSP is non-null and as restrictive as functional requirements allow | PASS (shape) | 7 assertions in `surfaces/gui/src/csp.test.ts` |
| Spreadsheet preview remains OFF until M02 passes | PASS | `capabilities.ts`; M02 is green and the capability is still OFF pending authorization |

### What changed and what did not

Upstream had already removed `allow-same-origin` and injected a `default-src 'none'` CSP
into artifact `srcdoc`. The E2E probe is extended to attempt the two things a hostile report
would actually want — the app's launch token via `parent.localStorage`, and the Tauri IPC
bridge — and both are unreachable because the frame has an opaque origin.

The application CSP was `null`. It is now `default-src 'self'` with `object-src 'none'`,
`base-uri 'self'`, `form-action 'none'`, `frame-ancestors 'none'`, no remote script origin,
no `unsafe-eval`, and `connect-src` limited to the local sidecar and Tauri IPC.

### Why `script-src` keeps `'unsafe-inline'`

Two reasons, and neither is convenience. `index.html` runs a pre-paint theme script; more
importantly, `srcdoc` frames **inherit the parent policy**, so removing it here would
silently kill the inline scripts report interactivity needs — inside a frame that is already
opaque-origin and already carries its own `default-src 'none'`. Recorded because "as
restrictive as functional requirements allow" is the actual bar, and this is where it sits.

### Honest limit

`tauri.conf.json` is applied by the **Tauri webview**. The E2E suite runs against Vite in a
plain browser, so these assertions lock the policy's *shape*, not its behaviour in the app.
A functional CSP check needs a desktop build on the launch platform — BLOCKED in this
environment, and recorded as such in `RELEASE_EVIDENCE.md`.

## M09 closure evidence — Durable State

| Acceptance boolean | Result | Evidence |
|---|---|---|
| Critical JSON stores use the shared atomic write helper | PASS | inbox, inbox_routing, mentions, unrouted, unattended, risk_overrides |
| Truncated / corrupt state cannot prevent startup | PASS | 9 corruptions x 6 stores = 54 construction cases |
| Recovery preserves the bad file for inspection without exposing sensitive content | PASS | quarantine keeps the bytes; the event carries store + reason + path only |
| Kill / interruption tests pass repeatably | PASS | interrupted-write, concurrent writers/readers, repeat-recovery |

**(72 cases.)**

### A defect the corpus found

`"items"` is *valid JSON* and a valid **string**. Guarding only against `JSONDecodeError`
would have let it through, and every store would then call `.get` on a `str` and raise out
of a boot-time constructor — the exact failure the module exists to prevent. `read_json_safe`
therefore validates the SHAPE the caller can use, not merely that the bytes parse.

### Recovery, not repair

The obvious repair — catch the error and start empty — passes "startup survives" and fails
the half that matters: it silently overwrites the only evidence, so nobody can tell
afterwards whether it was a disk-full crash or something worth investigating. Corrupt files
are renamed, never deleted, and the recovery event carries the store name, the reason and
the quarantine path — never the content, which would make the log a second copy of the thing
it is reporting.


## Ratified capability and residual-risk decisions — 2026-11-23

Recorded here because two of them are accepted residuals, not closed findings, and a ledger
that only lists closures misrepresents the posture.

| ID | Decision | Finding touched | Residual accepted |
|---|---|---|---|
| D-1 | Spreadsheet preview **ENABLED** | OW-SEC-002 | Legacy `.xls` previews are gone. The OLE2 binary path was the higher-risk surface, and the UI already routes spreadsheets to a real spreadsheet app, so this is a deliberate capability reduction rather than a regression. |
| D-2 | Remote MCP **stays OFF** | OW-SEC-009 | None. The corpus is green; the capability is held back by the strategy's pilot lock, not by missing evidence. |
| D-3 | Connector writes **stay OFF** | OW-SEC-004/005/007 | None, same reason. |
| D-4 | Active HTML preview **ratified ON** | OW-SEC-017 | **Yes.** The application CSP's shape is locked by 7 assertions and the artifact sandbox is proven at browser level, but the CSP's behaviour in the real Tauri webview is unverified in this environment. Accepted on the basis that the sandbox — not the app CSP — is the control protecting the preview, and that disabling the preview would have deleted the strongest regression lock in the corpus. |
| D-5 | Evidence refs pushed to origin | OW-SEC-000 (M01) | None. Closes a real gap: the refs were local-only and were lost when the container restarted mid-project. |
| D-6 | `script-src 'unsafe-inline'` **accepted** | OW-SEC-017 | **Yes.** `srcdoc` frames inherit the parent policy, so removing it would kill the inline scripts report interactivity needs. The frame is already opaque-origin with its own `default-src 'none'`, so the marginal exposure is an XSS in the app's own React code — which `object-src 'none'`, `base-uri 'self'`, `form-action 'none'` and the absence of any remote script origin still bound. |

### What is NOT covered by these decisions

OW-SEC-010 (browser automation) and OW-SEC-016 (native secret round-trip) were **not**
authorized, because neither prerequisite is met: the first is detection rather than
prevention, and the second has never been executed on the launch platform. Both capabilities
remain OFF and both are enforced by the `capability-defaults` CI job.
