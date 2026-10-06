# cti-backend

CVE intelligence API: JWT auth, RBAC + PBAC, user/role management, audit log, a CVE database fed from NVD, CISA KEV
and EPSS with fast search, and on top of it the asset inventory, CVE × asset matching, alerts, threat intel and reports.

Express 5 · TypeScript · Drizzle (PostgreSQL) · InversifyJS · Zod — Domain → Application → Infrastructure → Main.

## Run

```bash
docker compose up -d                 # postgres on :5440, redis on :6390
cp .env.example .env                 # set JWT_ACCESS_SECRET (>= 32 chars), SEED_ADMIN_*
npm install
npm run db:seed                      # migrations + permission catalog + system roles + first super_admin
npm run dev                          # API on :4000
```

CVE data is ingested by the separate **[cti-sync-worker](../cti-sync-worker)** service (NVD hourly, KEV every 6 h, EPSS daily,
full NVD load on first run). Start it next to the API: `cd ../cti-sync-worker && npm run dev`. The API only reads the data;
`POST /sync/:source/run` enqueues a BullMQ job (Redis, `REDIS_URL`) that the worker consumes — 503 if the queue is down.
This package owns the database migrations.
Schema changes: edit `src/infrastructure/database/schema/*` then `npm run db:generate` (never hand-write SQL).

## Auth model

- Access token: JWT (15 min). Refresh token: opaque, rotating, stored hashed, `httpOnly` cookie `cti_rt`
  scoped to `/api/v1/auth`; replaying a rotated token revokes the whole session family.
- Effective permissions = (role permissions ∪ user grants) − user denies (**deny wins**), cached 30 s and
  invalidated on change. Guards: no self role/permission changes, no granting what you don't hold,
  last active `super_admin` can't be removed, system roles can't be deleted.
- Registration is invite-only (`POST /users/invite` returns a one-time link). Password reset links are
  issued by admins (`POST /users/:id/reset-password`) until a mail channel exists.

## API (`/api/v1`)

| Area | Endpoints |
|---|---|
| Auth | `POST /auth/login \| refresh \| logout \| register \| reset-password \| change-password`, `GET /auth/me`, `GET /auth/invitations/:token`, `GET /auth/reset-tokens/:token` |
| Users | `GET/POST(invite) /users`, `GET/PATCH/DELETE /users/:id`, `PUT /users/:id/permissions`, `GET /users/:id/effective-permissions`, `POST /users/:id/reset-password \| revoke-sessions` |
| Roles | `GET /permissions`, `GET/POST /roles`, `GET/PATCH/DELETE /roles/:id` |
| Audit | `GET /audit` (keyset pagination) |
| CVE | `GET /cves` (`q, severity, cvssMin/Max, kev, epssMin, publishedFrom/To, vendor, product, cwe, sort, order, limit, cursor, includeTotal`), `GET /cves/stats`, `GET /cves/:id` |
| Assets | `GET/POST /assets`, `GET/PATCH/DELETE /assets/:id`, `POST /assets/import` (`dryRun` validates, otherwise saves), `GET /assets/imports` |
| Vulnerabilities | `GET /vulns`, `POST /vulns/status` (bulk status change), `POST /vulns/rematch`, `GET /cves/:id/assets` |
| Alerts | `GET/POST /alerts/channels`, `PATCH/DELETE /alerts/channels/:id`, `POST /alerts/channels/:id/test`, `GET/POST /alerts/rules`, `PATCH/DELETE /alerts/rules/:id`, `GET /alerts/log` |
| Intel | `GET/POST /intel/watchlists`, `PATCH/DELETE /intel/watchlists/:id`, `GET/POST /intel/iocs`, `DELETE /intel/iocs/:id` |
| Reports | `GET/POST /reports/schedules`, `PATCH/DELETE /reports/schedules/:id`, `GET/POST /reports/runs`, `POST /reports/runs/:id/retry`, `GET /reports/runs/:id/download` (CSV) |
| Sync | `GET /sync`, `POST /sync/:source/run` (enqueued in BullMQ; executed by cti-sync-worker) |

## Search performance notes

`tsvector` (GIN) + `pg_trgm` (GIN) for text, `text_pattern_ops` for CVE-id prefixes, B-tree
`(sort column DESC, id DESC)` per sort option with keyset pagination (no OFFSET), partial index for KEV,
GIN on `vendors` / `affected` / `cwe`. `cpe_matches` keeps compact version ranges for phase-2 asset matching.

## Inventory, matching and background jobs

- Assets carry software (`name` + `version`) and type-specific answers (web server, DB engine, firewall firmware…).
  Matching (`MatchAssetsService`) turns those into `vendor:product` + version, looks the product up in the CVE
  `affected` index and checks the version against the CPE ranges in `cpe_matches`. It runs after every asset
  create/update/import; `POST /vulns/rematch` redoes the whole inventory (e.g. after the CVE data grew).
  Software without a version is skipped — there is nothing to compare.
- Risk is additive and capped at 100: CVSS 30 · KEV 25 · EPSS 20 · internet-facing 15 · environment 10.
  Fix windows: KEV 3 d, CVSS ≥ 9 7 d, ≥ 7 30 d, ≥ 4 90 d, else 180 d, counted from when the match was first seen.
- The API process runs a one-minute tick: alert rules (new KEV / critical / EPSS ≥ 50 % matches, SLA reminders, sync
  failures, daily digest), watchlist notifications and report schedules. Channels: Slack incoming webhook, Telegram,
  generic webhook (HMAC `x-cti-signature` when a secret is set) and SMTP. Scheduled reports are mailed through the
  first SMTP channel.
- Reports are CSV only; PDF is not produced.
