# ReLead Ops

ReLead Ops is a production-oriented operations control plane for approved SSH work. It runs on Render, uses Supabase for auth/data/audit/configuration, and keeps Cloudflare as the preferred DNS and security edge.

It is not a generic shell. Commands must exist in the command catalog, be assigned to a target, pass role checks, and be confirmed with `EJECUTAR`. High-risk or destructive commands go through admin approval before the worker can execute them.

## Architecture

- `relead-ops-web`: Fastify UI/API, Supabase Auth, approvals, target onboarding, command catalog, audit, health dashboard and log streaming.
- `relead-ops-worker`: background worker that atomically claims confirmed queued jobs from Supabase, executes SSH, sends heartbeats, writes redacted log events, retries interrupted jobs and runs health checks.
- Supabase: `profiles`, `targets`, `commands`, `target_commands`, `executions`, `execution_log_events`, `health_checks`, `audit_logs`, `target_secrets`, permission tables and RPC claim functions.
- Render: Docker web service plus Docker worker service from `render.yaml`.
- Cloudflare: DNS, HTTPS, WAF/rate limiting and optional Access in front of `ops.relead.com.mx`.

## Safety Boundary

```text
catalog -> assign target -> plan -> EJECUTAR -> approval if needed -> worker claim -> SSH -> redacted logs
```

Production rules:

- no arbitrary host/user/command execution endpoint;
- no `StrictHostKeyChecking=no`;
- no secrets returned to the browser;
- service role key is server-side only;
- managed credentials are encrypted with AES-256-GCM using `SSH_KEY_ENCRYPTION_SECRET`;
- stdout/stderr are redacted and bounded before storage/streaming;
- destructive commands are cataloged as high risk and require approval.

## Local Verification

```bash
npm ci
npm run check
npm test
docker build -t relead-ops:local .
```

## Render Commands

```bash
npm run start:web
npm run start:worker
npm run dev:web
npm run dev:worker
```

## Required Production Variables

Minimum:

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
```

Worker:

```env
WORKER_ID=relead-ops-worker-render
WORKER_POLL_INTERVAL_MS=2500
WORKER_LOCK_SECONDS=90
WORKER_HEARTBEAT_INTERVAL_MS=10000
WORKER_STALE_SECONDS=300
HEALTH_CHECK_INTERVAL_MS=300000
MAX_CONCURRENT_JOBS=2
MAX_JOB_DURATION_SECONDS=300
MAX_LOG_BYTES=65536
```

Optional:

```env
OP_SERVICE_ACCOUNT_TOKEN=
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=600
```

## Documentation

- [Production rollout](docs/RELEAD_OPS_PRODUCTION.md)
- [Security model](docs/SECURITY.md)
- [Runbook](docs/RUNBOOK.md)
- [Tailscale architecture](docs/TAILSCALE.md)
- [ReleadServer setup](docs/RELEADSERVER_SETUP.md)
- [Cloudflare production](docs/CLOUDFLARE_PRODUCTION.md)
