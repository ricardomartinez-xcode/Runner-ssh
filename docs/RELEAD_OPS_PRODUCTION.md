# ReLead Ops Production

## Current Architecture

ReLead Ops runs as two Render services:

- `relead-ops-web`: Fastify UI/API, Supabase Auth, dashboards, target onboarding, approvals, audit and SSE log streaming.
- `relead-ops-worker`: Supabase-backed background worker for SSH execution, health checks, retries and interrupted job recovery.

Supabase is the coordination and audit backend. The worker claims jobs with `public.claim_execution()` using row locks and `SKIP LOCKED`, so two workers cannot claim the same execution.

## Supabase

Run migrations in order:

```bash
supabase db push
```

Or apply:

```text
supabase/migrations/0001_runner_admin.sql
supabase/migrations/0002_ssh_execution.sql
supabase/migrations/0003_managed_credentials_and_catalog.sql
supabase/migrations/0004_worker_approvals_permissions.sql
```

After first login, promote the first admin:

```sql
update public.profiles
set role = 'admin'
where email = 'ricardomartinez@relead.com.mx';
```

## Render

Use `render.yaml`. It defines:

- `relead-ops-web`, `dockerCommand: npm run start:web`
- `relead-ops-worker`, `dockerCommand: npm run start:worker`

Do not deploy this project to Vercel.

## Required Variables

```env
SUPABASE_URL=
SUPABASE_PUBLISHABLE_KEY=
SUPABASE_SECRET_KEY=
SSH_KEY_ENCRYPTION_SECRET=
AUTH_MODE=dual
OIDC_ISSUER_URL=
OIDC_JWKS_URL=
OIDC_AUDIENCE=
RUNNER_API_TOKEN_SHA256=
RUNNER_API_TOKEN_ROLES=runner.operator
MAX_CONCURRENT_JOBS=2
MAX_JOB_DURATION_SECONDS=300
MAX_LOG_BYTES=65536
```

Worker-specific:

```env
WORKER_ID=relead-ops-worker-render
WORKER_POLL_INTERVAL_MS=2500
WORKER_LOCK_SECONDS=90
WORKER_HEARTBEAT_INTERVAL_MS=10000
WORKER_STALE_SECONDS=300
HEALTH_CHECK_INTERVAL_MS=300000
```

## Deployment

1. Apply Supabase migrations.
2. Configure Render env vars on both services.
3. Deploy `relead-ops-web`.
4. Deploy `relead-ops-worker`.
5. Verify `/health` on the web service.
6. Sign in to `/admin`.
7. Install the recommended command catalog.
8. Add targets with `known_hosts` and a successful connection test.
9. Confirm high-risk command approval flow before enabling production targets.

## Backups and Recovery

- Back up Supabase tables daily.
- Back up `target_secrets` with the database, but keep `SSH_KEY_ENCRYPTION_SECRET` in Render secret storage.
- If `SSH_KEY_ENCRYPTION_SECRET` is lost, managed credentials cannot be decrypted and must be rotated.
- Interrupted jobs are requeued until `max_retries`; exhausted jobs are marked `failed` and `interrupted=true`.

## Validation

Before production:

```bash
npm run check
npm test
docker build -t relead-ops:production-check .
```

Then run one low-risk command against a staging target:

```text
whoami
hostname
uptime
df -h
```
