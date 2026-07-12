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
supabase/migrations/0005_ssh_cloudflare_targets_only.sql
supabase/migrations/0006_worker_instances.sql
supabase/migrations/0007_permission_enforcement.sql
supabase/migrations/0008_per_target_job_lock.sql
supabase/migrations/0009_backend_only_mutations.sql
supabase/migrations/0010_worker_connection_tests.sql
supabase/migrations/0011_command_safety_constraints.sql
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
SUPABASE_URL=https://hmhmhpyksqufclqzjkxo.supabase.co
SUPABASE_JWKS_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1/.well-known/jwks.json
SUPABASE_JWT_AUDIENCE=authenticated
SUPABASE_PUBLISHABLE_KEY=
SUPABASE_SECRET_KEY=
SSH_KEY_ENCRYPTION_SECRET=
AUTH_MODE=oidc
OIDC_ISSUER_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1
OIDC_JWKS_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1/.well-known/jwks.json
OIDC_AUDIENCE=authenticated
OIDC_REQUIRED_SCOPE=
OIDC_ROLE_CLAIMS=app_metadata.roles,app_metadata.role,roles,org_role
RUNNER_API_TOKEN_SHA256=
RUNNER_API_TOKEN_ROLES=runner.operator
MAX_CONCURRENT_JOBS=2
MAX_JOB_DURATION_SECONDS=300
MAX_LOG_BYTES=65536
```

JWT validation uses the Supabase JWKS at `/auth/v1/.well-known/jwks.json`. The verified production key id is `41cd089a-c0fc-44fe-bc70-d71fb746a16f` (`ES256`, `EC`, `P-256`). Keep the JWKS URL in configuration, not the full JWKS JSON. It is public verification metadata; the service role key, publishable key and credential encryption secret remain Render-managed values.

Worker-specific:

```env
WORKER_ID=relead-ops-worker-render
WORKER_POLL_INTERVAL_MS=2500
WORKER_LOCK_SECONDS=90
WORKER_HEARTBEAT_INTERVAL_MS=10000
WORKER_STALE_SECONDS=300
HEALTH_CHECK_INTERVAL_MS=300000
```

Optional break-glass variables belong only to `relead-ops-web`. Keep the feature disabled until the path-specific Cloudflare Access policy and Render SSH key are verified:

```env
BREAK_GLASS_ENABLED=false
BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS=true
BREAK_GLASS_KEY_SHA256=
BREAK_GLASS_SESSION_SECRET=
BREAK_GLASS_RENDER_PRIVATE_KEY=
BREAK_GLASS_RENDER_SERVICE_ID=
BREAK_GLASS_RENDER_SSH_HOST=
BREAK_GLASS_RENDER_KNOWN_HOSTS=
CLOUDFLARE_ACCESS_TEAM_DOMAIN=
CLOUDFLARE_ACCESS_AUD=
```

See `docs/BREAK_GLASS.md`; `/bash` is deliberately not part of Supabase administrator authorization or the catalog execution flow.

## Deployment

1. Apply Supabase migrations.
2. Configure Render env vars on both services.
3. Deploy `relead-ops-web`.
4. Deploy `relead-ops-worker`.
5. Verify `/health` on the web service.
6. Sign in to `/admin`.
7. Install the recommended command catalog.
8. Add only `ssh` or `cloudflare_tunnel` targets with `known_hosts` and a successful connection test.

Connection tests are durable Supabase jobs claimed by `relead-ops-worker`. New targets are inserted disabled, and `enable_on_success` activates them only after the worker persists a successful SSH result.
9. Confirm high-risk command approval flow before enabling production targets.
10. Separately test Render native SSH before enabling the `/bash` break-glass proxy.

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
