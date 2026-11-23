# Security hardening

This document lists the controls built into SentinelOps v2 and where they live.

## Authentication & session
- **Stateless JWT** (HS256). No server session, no auth cookie, so there is no
  CSRF surface on the API. `security/JwtService.java`, `security/JwtAuthFilter.java`.
- **Fail-closed secret.** The app refuses to start unless `JWT_SECRET` is set and
  ≥ 32 bytes. No insecure default. `JwtService.init()`.
- **Short token TTL** (default 30 min), configurable.
- **BCrypt** password hashing, strength 12. `config/SecurityConfig.passwordEncoder()`.
- **Uniform login failure** — the API never reveals whether an email exists. `web/AuthController`.

## Target authorization and scope (Phase 1)
- **Verify, then authorize, then scan.** Registering a target gives no permission. Ownership is proven (DNS TXT / HTTP
  file / recorded owner + network-team approval) and expires; a signed authorization with a window, permitted methods and
  exclusions is a separate requirement. `service/AuthorizationGateService`.
- **Address policy at every use.** DNS is resolved fresh at registration, at every gate check and when a scan executes;
  every resolved address must pass `service/ScopeValidator` (no loopback, private, link-local/metadata, multicast,
  reserved, IPv6 local, this server, or configured addresses). A record that is changed to point inside the network after
  approval is caught.
- **Lab exception is narrow:** ADMIN-registered lab target + allowlisted host + inside the lab CIDR + lab feature
  enabled + a signed authorization. It never relaxes the rules for any other target.
- **SSRF-safe verification:** the HTTP-file check refuses hosts resolving to forbidden addresses, never follows
  redirects, and reads at most 1 KiB. DNS checks use independent resolvers.
- **Active scanning needs three things:** the authorization allows it, an ADMIN switched the global DB setting on
  (default off), and ACTIVE was requested; anything else is PASSIVE.
- **Four-eyes approval** (configurable): the approver of an authorization must differ from the requester.
- **Object-level access:** a CLIENT user sees only their own client's engagements, targets, authorizations and findings.
- **Refusals are audited:** audit entries use their own transaction, so a denied scan or rejected target is recorded even
  though the request itself is rolled back.

## Authorization
- **Deny-by-default**: every route requires authentication unless explicitly public.
- **Role-based access** at the route level plus **method security** (`@PreAuthorize`)
  on sensitive services (`ScanService.requestScan`, `AuthorizationService.sign`).
- **The authorization gate** is the domain's core control: a scan runs only when a
  signed, in-window authorization lists the target host. Re-checked at execution
  time, not just at request time. `service/AuthorizationGateService`, `service/ScanService`.
- **Strict scope allowlist** — exact host or subdomain match only, no wildcards.

## Input handling & data access
- **Bean Validation** on every request DTO (`dto/*`), with a global handler that
  returns field errors without stack traces. `web/GlobalExceptionHandler`.
- **JPA / parameterized queries** throughout — no string-built SQL.
- **Schema owned by Flyway**; Hibernate is `ddl-auto: validate` (never auto-mutates
  the database). MySQL migrations live in `db/migration`.

## Transport & headers
- **HSTS** (1 year, includeSubDomains), **X-Frame-Options: DENY**,
  **X-Content-Type-Options: nosniff**, **Referrer-Policy: no-referrer**,
  a restrictive **Content-Security-Policy**, and **Permissions-Policy**. `SecurityConfig`.
- **CORS allowlist** from configuration; credentials disabled.

## Abuse resistance
- **Per-IP rate limiting** (token bucket) ahead of authentication. `security/RateLimitFilter`.
  (Back it with Redis for multi-instance deployments.)

## Operational
- **Actuator** limited to `/health` publicly; everything else requires ADMIN.
- **Append-only audit log** of every gate decision, authorization, and scan. `service/AuditService`.
- **No error leakage**: server error messages and stack traces are never returned
  to clients (`server.error.*` + the global handler).
- **Secrets via environment only** — nothing sensitive is committed; `.env.example`
  documents the variables.

## Scanning safety
- **Global active-scan kill-switch** (`ALLOW_ACTIVE_SCAN`). Active scanning needs
  **both** the per-engagement RoE flag and the global switch; otherwise a run is
  downgraded to passive. `ScanService.resolveMode`.
- **Identifier header** added to all scanner traffic so client defenders can tell
  an authorized test from a real attack.
- **Candidate findings** require tester validation before reaching a client.

## Recommended before production
- Put the API behind TLS termination; enforce HTTPS end to end.
- Move rate limiting and any run queue to Redis; add a durable job runner so scans
  survive restarts.
- Add refresh-token rotation and token revocation if longer sessions are needed.
- Add dependency and container scanning to CI; pen-test the platform itself.

## Scan engine (Phase 2)
- **One launcher, one command shape.** Only `service/scanner/DockerRunner` starts containers:
  `docker run --rm --name sentinelops-<tool>-<run> --cap-drop ALL --security-opt no-new-privileges --pids-limit --memory --cpus ...`,
  built as an argument list (no shell). It rejects names, images, networks and arguments outside strict patterns.
  Docker-group access is root-equivalent, so this class stays small and is unit-tested.
- **Inputs are re-validated** in `ScanContext.of` right before they reach a command line: host charset (cannot start
  with `-`), URL must be http(s), on the authorized host, no credentials, no shell characters, safe header name/value.
- **Tool choice is server-side:** WEB = Nuclei + ZAP, API = Nuclei, TLS = testssl, NETWORK = Nmap. Clients cannot pass flags.
- **Passive by default.** PASSIVE: ZAP baseline (no attacks), Nuclei exposure/misconfiguration checks without CVE
  templates and with intrusive/DoS/fuzz/brute-force tags excluded, Nmap TCP connect scan of the top 100 ports.
  ACTIVE (ZAP full scan, Nuclei CVE templates, Nmap version detection) needs all three switches and is re-evaluated when
  the run starts, so turning the global switch off downgrades queued runs.
- **Gate twice.** The gate runs when the scan is requested and again just before the container starts, with fresh DNS.
  The container gets the gate-approved IPv4 addresses via `--add-host`, so DNS cannot be switched between check and connect.
- **Lab isolation.** Lab targets are scanned only on the lab Docker network (internal, no internet, no published ports).
- **Containers:** all capabilities dropped, no-new-privileges, memory/CPU/PID limits, timeout (then `docker rm -f`),
  raw output capped at 20 MB, XML parsed with DOCTYPE disabled.
- **Durable queue.** The queue is the `scan_run` table; runs are claimed atomically; runs interrupted by a restart are
  marked FAILED (never silently re-run). Stop removes the container.
- **No invented results.** A run is COMPLETED only when the tool exited acceptably AND its output parsed. Missing or
  unreadable output is FAILED. Findings are de-duplicated by target + tool + rule + location.
- **Known limits:** a site that redirects a scanner to another host is stopped only by the tool's own behaviour unless the
  host firewall also blocks private ranges from the scan network (see DEPLOYMENT_GUIDE section 8). A stop request racing
  with a tool that finishes at the same instant can still be recorded as completed.

## Findings, reports and advanced scanning (Phases 3-5)
- **Confirm before the client sees it.** Scanner results are candidates (`validated=false`). Only a tester can confirm
  or dismiss them. A CLIENT user sees, counts and reports only confirmed findings, even if they ask for candidates.
- **Controlled status workflow.** `RETEST_PASS` / `RETEST_FAIL` are set only by the retest worker, never by hand.
  A CLIENT may only report progress (IN_PROGRESS / FIXED); they cannot dismiss, close or mark a retest as passed.
- **A retest can only pass honestly:** it needs a COMPLETED run of the same tool on the same target; a failed, timed-out
  or stopped run settles nothing; a passive run cannot prove an ACTIVE finding fixed; a finding that returns is reopened.
- **Reports** are built only from stored facts, state their limits, list every scan run, and are audited with a SHA-256.
  Text from scanners is sanitised before it enters the PDF.
- **Authenticated scans** need all of: a signed authorization with "authenticated testing" ticked, a stored credential,
  and a WEB/API scan. The value is AES-256-GCM encrypted (key in `sentinelops.security.secret-key`, storing is refused
  without it), write-only (never returned, never in audit or logs, scrubbed from tool output). It reaches the tool
  through a short-lived 0600-style file (Nuclei) or the process environment (ZAP, limited to the target host), never
  a command line; the work folder is owner-only. Routing headers (Host, Content-Length, ...) are refused.
  Residual risk: a tool that follows a redirect to another host could send the header there. Use a low-privilege test account.
- **OpenAPI import** must be on the target's own host; the ZAP API scan forces requests to that host (`-O`) and only
  runs in ACTIVE mode (it is an attack scan by nature).
- **Schedules** never bypass the gate: they call the same `ScanService.enqueue` path, record each refusal, and switch
  themselves off after three refusals in a row. Nothing is consumed while the engine is switched off.
