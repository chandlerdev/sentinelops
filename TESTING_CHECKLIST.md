# Testing checklist - check everything, phase by phase

Tick each line yourself. If something is wrong, note the page, what you clicked and the message you saw, and send it to me.
Parts A is on your PC (no Docker needed). Part B needs Docker. Part C is the server.

Local addresses: UI http://localhost:3200/sentinelops  -  API http://localhost:8280/api
Start them if they are not running:

```
# backend (first run on an EMPTY database also creates the admin)
cd sentinelops_backend
set SEED_ADMIN_PASSWORD=admin@1234
mvn spring-boot:run -Dspring-boot.run.profiles=seed      # later runs: mvn spring-boot:run
# admin app
cd sentinelops_admin
npm run dev
```

Accounts. The first one is created by the seed. For the others create them yourself (Users page, as admin):
`admin@sentinelops.local` / `admin@1234` (ADMIN), plus one MANAGER, one TESTER and one CLIENT (link the CLIENT to "Demo Client").
If the database still holds my old test data, it is easiest to reset it (drop and recreate the `sentinelops` database) and restart the backend.

---------------------------------------------------------------------

## PART A - on this PC

### Phase 0 - foundation
- [ ] Open http://localhost:3200/sentinelops/status: shows **All systems operational** and database UP.
- [ ] Open http://localhost:8280/api/health: JSON with `"status":"UP"`.
- [ ] Login page: wrong password shows an error; right password opens the app.
- [ ] Log out and try to open `/sentinelops/clients` directly: you are sent to the login page.
- [ ] The tab titles and the top menu look right for each role (CLIENT sees no Clients / Users / Settings / Audit log).

### Phase 1 - targets and authorization
- [ ] **Users** (admin): create a MANAGER, a TESTER and a CLIENT user. A CLIENT must be linked to a client.
- [ ] **Clients** (manager): create a client. **Engagements**: create one for it; it starts at "awaiting authorization".
- [ ] Engagement page, as TESTER, **register targets**. Each of these must be REFUSED with a clear message:
      `127.0.0.1`, `10.0.0.5`, `192.168.1.1`, `169.254.169.254`, `localhost`, `*.example.com`, `0.0.0.0/0`.
- [ ] Register a real domain you own (for example your own site). Status shows **UNVERIFIED**.
- [ ] **Gate check** on it (dry run): it says DENIED, "not verified".
- [ ] **Verify via DNS**: it shows the TXT record name and value. Click **Check now** before adding the record: it must fail honestly.
- [ ] (Optional, only if you really own the domain) add the TXT record, **Check now**: it becomes VERIFIED.
- [ ] Register an IP target. As MANAGER use **Record owner approval** (a TESTER must not see this button).
- [ ] **Authorizations**: create a draft as TESTER, **Submit**, then approve it as MANAGER (the same person cannot approve their own if four-eyes is on).
      Check the gate check changes from DENIED to ALLOWED only after approval; **Revoke** closes it again.
- [ ] **Settings** (admin): the "active scanning" switch is OFF by default; a manager cannot change it.
- [ ] **Audit log**: shows the steps above, including the REFUSED targets and denied gate checks.

### Phase 2 - scan engine (without Docker you can only check the safe failure)
- [ ] With an ALLOWED target, press **Request scan** (WEB, PASSIVE): two runs appear under **Scans** (nuclei, zap).
- [ ] Because this PC has no Docker, both end **FAILED** with a clear reason, and **no findings** are created. That is correct.
- [ ] A denied target (not verified / not authorized) gives a clear refusal and creates no runs.
- [ ] TLS on a target whose base URL is http:// is refused ("needs an https target").
- [ ] CLIENT user: cannot see the scan request form or the Stop button.

### Phase 3 - findings and dashboard
(No scanner has run here, so there are no real findings yet. You will see them after Part B. Check the screens now.)
- [ ] **Dashboard** (menu): numbers, severity bars, one row per engagement, links work.
- [ ] Engagement page, top: **Status** box with counts and bars.
- [ ] Findings card: filters (severity / status / tool) are present and do not break the page.
- [ ] CLIENT user sees the Dashboard and engagement but **not** "Candidates to review".

### Phase 4 - report and retest
- [ ] Engagement page, Findings card: **PDF report** downloads a file that opens. It lists the client, the targets, the signed authorization, method and limits.
- [ ] **Draft incl. candidates** (staff only) also downloads; CLIENT does not have this button.
- [ ] The retest buttons appear after Part B (they need a finding that is marked FIXED).

### Phase 5 - authenticated scans, OpenAPI, schedules
- [ ] A target's **Login & API** button: saving a header (for example `Authorization` + any dummy value) says it was saved and then shows only the header NAME, never the value.
- [ ] Saving a credential for header `Host` is refused.
- [ ] **Remove** deletes it. OpenAPI URL on another site's host is refused; on the target's own host it is accepted.
- [ ] Authorization form has "allow AUTHENTICATED testing". A credential is used only when that is ticked.
- [ ] **Recurring scans**: add a schedule (target, WEB, PASSIVE, 7 days); it is listed with the next run time; **Pause / Resume / Delete** work.

---------------------------------------------------------------------

## PART B - first real scans (needs Docker on this PC)

1. Install **Docker Desktop**, start it, and run `docker run --rm hello-world` once.
2. In `sentinelops_backend/src/main/resources/application.properties` set:
   `sentinelops.scan.lab.enabled=true`, `sentinelops.scan.lab.cidrs=172.28.0.0/24`, `sentinelops.scan.lab.hosts=juice-shop`
   (the engine is already enabled locally). On Windows the lab name must resolve: add `172.28.0.10 juice-shop` to
   `C:\Windows\System32\drivers\etc\hosts` (edit as administrator), and note that Docker Desktop on Windows may not
   expose the container network to the PC - if the gate cannot resolve it, tell me and I will adapt it.
3. `docker compose -f lab/docker-compose.yml up -d`
4. In the UI as ADMIN: engagement -> register target `juice-shop`, tick **Lab asset**, base URL `http://juice-shop:3000`
   -> draft an authorization (WEB, API, TLS not needed) covering it -> submit -> approve -> **Request scan** WEB / PASSIVE.
5. Expected: two runs (nuclei, zap) go QUEUED -> RUNNING -> COMPLETED and findings appear. It is quite likely that a flag or
   a parser needs a small fix on this first real run: send me the run error text and I will fix it.
6. Check the findings: **Confirm** one, mark another **False positive**, move a confirmed one to **Fixed**,
   press **Request retest** and check the status changes to RETEST_PASS or RETEST_FAIL.
7. Download the PDF report and read it as if you were the client.

---------------------------------------------------------------------

## PART C - on the server (follow DEPLOYMENT_GUIDE.md in order)

- [ ] Section 0: pre-checks (ports 3017 and 8096 free).
- [ ] Section 2b: test the migrations on MySQL 8 in a throwaway database (expects "applied 4 migrations").
- [ ] Sections 2-5: database, upload, backend, admin app. Check `curl http://127.0.0.1:8096/api/health`.
- [ ] Section 6: Apache change - **ask first**, back up, `configtest`, `reload` (never restart). Existing site still works.
- [ ] Section 7: https://jjlltdnext.desss-portfolio.com/sentinelops/status and /login.
- [ ] Section 8 only after Docker is approved and the network-security person has been told.
- [ ] Set `sentinelops.scan.blocked-addresses=75.148.178.10` before anything else.
