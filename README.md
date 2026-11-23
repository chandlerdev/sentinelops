# SentinelOps v2

Authorized penetration-testing / VAPT platform: **Spring Boot** backend,
**Next.js** admin app, **MySQL** database.

```
sentinelops-v2/
├── sentinelops_admin/     # Next.js app, served under /sentinelops
├── sentinelops_backend/   # Spring Boot API (endpoints under /api)
│   └── src/main/
│       ├── java/com/sentinelops/
│       │   config/ controller/ dto/ entity/ exception/
│       │   repository/ security/ service/ util/
│       └── resources/
│           application.properties          (git-ignored, per site)
│           application.properties.example  (copy this)
│           db/migration/                   (Flyway, MySQL)
├── lab/                   # Juice Shop lab (docker compose, internal network)
├── _unused/               # local-only (old demos), never pushed
├── DEPLOYMENT_GUIDE.md    # Ubuntu server steps (prepared, not yet executed)
├── IMPLEMENTATION_STATUS.md
├── SECURITY.md
└── .gitignore
```

## URLs

| | Local (this PC) | Server |
|---|---|---|
| Admin app | http://localhost:3200/sentinelops | https://jjlltdnext.desss-portfolio.com/sentinelops |
| API | http://localhost:8280/api | https://jjlltdnext.desss-portfolio.com/sentinelops-api |
| Ports | 3200 / 8280 | 3017 / 8096 |

Health check: `GET /api/health` (public). Status page: `/sentinelops/status`.

## Run locally

Needs Java 21, Maven, Node, and MySQL/MariaDB with an empty `sentinelops` database.

Backend:

```bash
cd sentinelops_backend/src/main/resources
cp application.properties.example application.properties   # then set DB user/password, jwt secret, port 8280
cd ../../..
# first run on an empty database also creates the demo admin:
SEED_ADMIN_PASSWORD='<10+ chars>' mvn spring-boot:run -Dspring-boot.run.profiles=seed
# afterwards:
mvn spring-boot:run
```

Admin app:

```bash
cd sentinelops_admin
cp .env.example .env.local      # NEXT_PUBLIC_API_BASE=http://localhost:8280/api
npm install
npm run dev                     # http://localhost:3200/sentinelops
```

Demo login (seed profile): `admin@sentinelops.local` / the `SEED_ADMIN_PASSWORD` you set.

## Roles

| Role | Can do |
|---|---|
| ADMIN | everything: users, global active-scanning switch, lab targets, audit log |
| MANAGER | clients, engagements, record IP ownership approvals, approve / reject / revoke authorizations, audit log |
| TESTER | register targets, start domain verification, draft and submit authorizations, gate checks, request scans |
| CLIENT | read-only view of their own client's engagements, targets, authorizations and findings |

## API (all under `/api`, JWT bearer token)

| Area | Endpoints |
|---|---|
| Auth / health | `POST /auth/login`, `GET /health` |
| Admin | `GET,POST /users`, `GET /settings`, `PUT /settings/active-scanning`, `GET /audit` |
| Clients / engagements | `GET,POST /clients`, `GET,POST /engagements`, `GET /engagements/{id}` |
| Targets | `GET,POST /engagements/{id}/targets`, `POST .../targets/{tid}/verification` (DNS_TXT or HTTP_FILE), `.../verification/check`, `.../verification/manual` (IP/CIDR), `.../gate-check` (dry run) |
| Authorizations | `GET,POST /engagements/{id}/authorizations`, `POST /authorizations/{id}/submit | approve | reject | revoke` |
| Scans / findings | `POST /engagements/{id}/scan` (gate-enforced, queues one run per tool), `GET /engagements/{id}/scans`, `POST /scans/{id}/stop`, `GET /engagements/{id}/findings` |

## Tests

```bash
cd sentinelops_backend
mvn test        # 148 unit tests: gate, scope/SSRF policy, verification, authorization, scan runner, queue, parsers, findings, retests, reports, schedules, credentials
```

## The invariant

No scan runs unless a matching authorization is **signed, in-window, and lists
the target host**. Enforced server-side in `service/AuthorizationGateService.java`
and re-checked at execution time in `service/ScanService.java`. See **SECURITY.md**.

## Phases 3-5 (findings, reports, advanced)

| Area | Endpoints |
|---|---|
| Findings workflow | `GET /engagements/{id}/findings?severity=&status=&tool=`, `GET /findings/{id}`, `POST /findings/{id}/validate`, `PUT /findings/{id}/status`, `POST /findings/{id}/retest` |
| Dashboard | `GET /dashboard`, `GET /engagements/{id}/dashboard` |
| Report | `GET /engagements/{id}/report?includeCandidates=false` (PDF) |
| Schedules | `GET,POST /engagements/{id}/schedules`, `PUT /schedules/{id}/enabled`, `DELETE /schedules/{id}` |
| Authenticated scans | `PUT,GET,DELETE /engagements/{id}/targets/{tid}/credential` (value is write-only), `PUT .../targets/{tid}/openapi` |

See `TESTING_CHECKLIST.md` for how to check everything, phase by phase.
