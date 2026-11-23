# Implementation status

## Phase 0 – Foundation (local): DONE
See README. Folders `sentinelops_admin` / `sentinelops_backend`, base path `/sentinelops`, health endpoint, status page.

## Phase 0 – Server deployment: PREPARED, NOT EXECUTED
See `DEPLOYMENT_GUIDE.md`. Needs: DB creation (sudo), code upload, PM2 start, Apache change (approval + backup + configtest + reload).

## Phase 1 – Targets and authorization: DONE (local)

**What exists**
- Roles enforced in the backend (route rules + `@PreAuthorize`): ADMIN, MANAGER, TESTER, CLIENT. A CLIENT user is linked to one client and only sees that client's engagements and findings.
- Users (ADMIN creates), clients, engagements (start at `AWAITING_AUTHORIZATION`), audit log (append-only, written in its own transaction so refusals are recorded).
- **Targets**: domain, IP or CIDR (IPv4 /24 or smaller, IPv6 /120 or smaller). URL input is reduced to its host. Hostile input is refused at registration.
- **Ownership verification**: domain via DNS TXT (`_sentinelops-challenge.<domain>`, value `sentinelops-verify=<token>`, looked up through independent DNS servers) or an HTTP file (`/.well-known/sentinelops-verify.txt`, no redirects, 1 KiB cap, refuses hosts that resolve to forbidden addresses). Tokens expire (72 h); a successful verification expires (30 d) and can be repeated. IP/CIDR via a recorded manual approval (system owner + network-team acknowledgement + evidence), MANAGER/ADMIN only.
- **Written authorization**: per engagement, covers a set of targets, permitted methods (WEB/API/NETWORK/TLS), exclusions, window, active-testing permission, approver, emergency contact, evidence reference. Workflow DRAFT → PENDING_APPROVAL → SIGNED | REJECTED, SIGNED → REVOKED. Approval refused while a target is unverified or the window has ended; optional four-eyes rule (approver ≠ requester).
- **Authorization gate** (`AuthorizationGateService`), checked at request time and again at execution time: target in engagement, ownership valid, signed authorization covers it, in window, not expired, method permitted, not excluded, and a **fresh DNS resolution** passes the address policy.
- **Scope policy** (`ScopeValidator`): blocks loopback, RFC 1918, CGNAT, link-local incl. 169.254.169.254, multicast/reserved, IPv6 local ranges, every address of this server, and configured addresses. **Lab exception** only for ADMIN-registered lab targets, allowlisted hosts, inside the lab CIDRs, with the lab feature enabled.
- **Active scanning** needs ALL of: authorization allows it, the ADMIN global switch is on (stored in DB, default OFF), and ACTIVE requested. Otherwise PASSIVE.
- Scan endpoint runs the gate and records a scan run. **No scanner exists yet**: a permitted run ends FAILED with "Scanner engine not implemented yet (arrives in Phase 2)". No result is ever invented. Dry-run gate check endpoint for the UI.
- Admin UI: engagements, clients, users, settings (active-scanning switch), audit log, engagement page with targets, verification, gate check, authorizations and scan request.

**Tests** (59 unit tests, all passing): `mvn test` in `sentinelops_backend`. Cover the gate, scope/SSRF policy, DNS change at scan time, lab exception, verification (DNS, HTTP, manual, expiry), authorization workflow and four-eyes, active-mode switches, parsing. Sanity-checked by temporarily breaking the metadata block and the verification check (tests failed as expected, code restored).
Plus a 58-check end-to-end run against the real API on a fresh MariaDB (roles, object-level access, hostile targets, full approval flow, revoke, audit). It found and fixed one real bug: refused attempts were rolled back out of the audit log.

**Decisions**
- Authorization is per engagement and target-based; the old per-technology model was replaced (`V2__targets_and_authorization.sql`, additive to V1).
- New engagements start at `AWAITING_AUTHORIZATION` (sales steps are outside this platform).
- DTOs everywhere in the new API; no entities returned (the findings endpoint still returns the entity until Phase 3).
- UI uses plain inline styles (no Tailwind), kept from the prototype.

## Phase 2 - Scan engine: BUILT, NOT YET RUN AGAINST REAL CONTAINERS

**What exists**
- Persistent job queue (`scan_run` table, atomic claim, restart recovery, stop) - `ScanWorker`, `ScanService`.
- `ScanExecutor`: gate re-check with fresh DNS -> validated `ScanContext` -> one container per tool -> parse -> store findings -> COMPLETED/FAILED. Active mode re-evaluated at start. Timeout, output cap, de-duplication.
- `DockerRunner`: single fixed command template (cap-drop ALL, no-new-privileges, limits, gate-approved IPs pinned with `--add-host`, lab targets only on the lab network).
- Adapters with fixed command templates and parsers: Nuclei (WEB, API), ZAP baseline / full (WEB), testssl (TLS), Nmap connect scan (NETWORK).
- Findings now carry tool, rule, location, description, how-to-fix, references, fingerprint, last seen (`V3__scan_engine.sql`).
- `lab/docker-compose.yml` (our Juice Shop on an internal network, no published ports).
- API: queue per tool, `GET /engagements/{id}/scans`, `POST /scans/{id}/stop`. UI: Scans panel (auto-refresh, Stop), expandable findings.
- Engine is OFF by default (`sentinelops.scan.engine.enabled=false`).

**Evidence**: 103 unit tests pass (runner command shape, input validation, parsers, executor with a fake Docker, queue, stop); 64-check e2e on a fresh MariaDB (V1-V3 applied, queue picks runs up, without Docker they FAIL honestly with zero findings, audit, access rules); tsc clean.

**NOT verified (be honest)**
- **No Docker on the dev PC, so no tool has ever run.** The command-line flags for Nuclei, ZAP, testssl and Nmap and the output parsers follow each tool's documentation but were never checked against real output. Expect small fixes on the first lab run (e.g. a flag name, ZAP output folder permissions, Nuclei template download time).
- Image tags (`:latest`, `drwetter/testssl.sh:3.2`, ...) were not pulled; pin versions once working.
- `internal: true` lab network and the `/etc/hosts` name resolution for `juice-shop` are untested.
- Scanner egress to the company network is not blocked by the platform itself; needs the host firewall rule (DEPLOYMENT_GUIDE section 8).
- Findings list is still sorted by severity text in the API (alphabetical); the UI sorts correctly. Proper ordering, dashboard, status workflow: Phase 3.
- One backend instance assumed (restart recovery fails every RUNNING run). Stop racing with a finishing tool can record COMPLETED.
- Authenticated scans, OpenAPI import, schedules: Phase 5.

## Phase 3 - Findings and dashboard: BUILT (local)
- Findings carry validation (candidate -> confirmed / false positive), status workflow (OPEN, IN_PROGRESS, FIXED, RETEST_PASS/FAIL, CLOSED, FALSE_POSITIVE) with per-role rules, filters, worst-first ordering (the old alphabetical-severity ordering is gone), notes.
- Dashboard endpoints and pages (global + per engagement): open by severity, awaiting retest, resolved, candidates, targets verified, scans running/failed. CLIENT sees only confirmed findings.

## Phase 4 - Report and retest: BUILT (local)
- PDF report (OpenPDF): cover, executive summary, scope + signed authorization, method and limits, findings with fix advice and retest history, scan-run appendix; audited with SHA-256. CLIENT always gets confirmed findings only.
- Retest: request on a FIXED finding queues only the tool that found it; the worker settles it (PASS / FAIL) only from a COMPLETED run; passive cannot prove an active finding fixed; a returning finding is reopened.

## Phase 5 - Advanced: BUILT (local)
- Authenticated scans: per-target credential header, AES-256-GCM at rest, write-only, needs "authenticated testing" in the signed authorization; passed by file (Nuclei) / environment (ZAP), never on a command line.
- OpenAPI import (own host only) + ZAP API scan (ACTIVE only, requests forced to the authorized host).
- Recurring scans through the normal gate; auto-off after 3 refusals.

**Evidence**: 148 unit tests pass; 101-check end-to-end run on a fresh MariaDB (V1-V4 applied): workflow, filters, dashboards, failed retest does not pass, PDF download, schedules, credential never in API/DB/audit, role checks. A bug found by the tests and fixed: container names rejected the tool id "zap-api".

**NOT verified (be honest)**
- Still no real tool run (no Docker on the dev PC): all Phase 2-5 command lines, parsers and ZAP/Nuclei auth options are from documentation. Specifically unconfirmed: Nuclei `-H <file>`, ZAP `ZAP_AUTH_HEADER*` env vars, `zap-api-scan.py -O`.
- Findings workflow and report were exercised with three synthetic rows (deleted after the test) and unit tests, not with real scanner output.
- The PDF text was checked by extraction in a unit test; I could not render the pages to look at the layout.
- The UI for Phases 3-5 compiles (tsc) but was not clicked through in a browser.
- The e2e check "client sees only confirmed findings" is covered by unit tests; the e2e client belongs to another client than the test engagement.
- MySQL 8 has run none of V2-V4 yet.
- Schedules: one backend instance assumed; the first run is about 10 minutes after creation.

## Known gaps / risks (honest list)
- UI was compiled (tsc) and every page returns 200, but **I have not clicked through it in a browser**.
- The V2 migration ran on **MariaDB 10.4 only**. MySQL 8.0 (server) is untested; `DROP INDEX uq_auth_eng_tech` is the statement to watch. Run the migration on the server in a throwaway DB first.
- HTTP-file verification validates the host's addresses and then connects by name; a DNS change in that tiny window is theoretically possible (documented residual risk; no redirects are followed).
- The JWT role claim is trusted until the token expires (30 min); disabling a user takes effect at next login. No user disable/reset-password UI yet.
- Blocking "this server's own IP" relies on the local interface list plus `sentinelops.scan.blocked-addresses` (set the server's public IP there on the server).
- Redirect / scope-expansion control still depends on tool behaviour plus a host firewall rule (see Phase 2).
- (Replaced in Phase 2: scans now run in the queue worker.)
- No soft delete, no document upload for authorization evidence (a reference string is stored).

## Not started
- (Phase 2 is built, see above; it still needs its first real run on the server lab)
- (Phases 3-5 are built, see above. Nothing left in the plan except the real-world checks in TESTING_CHECKLIST.md.)
