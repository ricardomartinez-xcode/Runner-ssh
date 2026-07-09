# ReLead Ops production rollout

ReLead Ops is the evolution of Runner SSH into an infrastructure operations control plane.

It keeps the existing safe runner boundary:

```text
list -> plan -> explicit EJECUTAR -> execute -> read redacted log
```

And adds Supabase as the administrative source of truth for:

- users and roles;
- SSH/Codespaces/Tailscale/Cloudflare targets;
- command catalog;
- execution history;
- health dashboard;
- audit logs.

## 1. Supabase setup

Create a Supabase project and run:

```bash
supabase/migrations/0001_runner_admin.sql
```

Then create the first admin user:

```sql
update public.profiles
set role = 'admin'
where email = 'ricardomartinez@relead.com.mx';
```

Do this only after signing in once through Supabase Auth so the profile exists.

## 2. Auth decision

For the Admin UI, use Supabase Auth.

For the runner API, keep the current OIDC/api_token mode during migration. After the UI is stable, move execution requests to Supabase-issued sessions or a private worker token.

Recommended production mode during transition:

```env
AUTH_MODE=dual
```

## 3. Render service

Create or sync the Render Blueprint using `render.yaml`.

Service name:

```text
relead-ops-api
```

Required environment variables:

```env
SUPABASE_URL=
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=
SSH_KEY_ENCRYPTION_SECRET=
AUTH_MODE=dual
OIDC_ISSUER_URL=
OIDC_JWKS_URL=
OIDC_AUDIENCE=
RUNNER_API_TOKEN_SHA256=
RUNNER_API_TOKEN_ROLES=runner.operator
OP_SERVICE_ACCOUNT_TOKEN=
RUNNER_GITHUB_TOKEN=
```

Never commit private keys, raw tokens, passwords, OAuth secrets or Supabase service-role keys.

## 4. DNS and domain

Recommended domain:

```text
ops.relead.com.mx
```

Point it to Render using the DNS records Render provides.

## 5. Initial production checklist

Before exposing the service publicly:

- Supabase RLS enabled.
- First admin promoted manually.
- `SUPABASE_SERVICE_ROLE_KEY` stored only in Render.
- Runner API protected by OIDC or static token hash.
- No shell-free arbitrary command endpoint.
- Only allowlisted commands.
- High-risk commands require approval.
- Audit logs enabled.
- Render health check passes at `/health`.

## 6. MVP phases

### Phase A — Current branch

- Rename project to ReLead Ops.
- Add Supabase schema.
- Add Render production variables.
- Keep current runner API working.

### Phase B — Admin UI

Add a web UI with:

- login;
- dashboard;
- targets CRUD;
- commands CRUD;
- execution history;
- health cards.

### Phase C — Worker integration

Make the runner read targets and commands from Supabase instead of only `config/runner.yaml`.

### Phase D — Advanced ops

Add:

- Tailscale-aware targets;
- Cloudflare Tunnel targets;
- Codespaces lifecycle actions;
- realtime logs;
- approval flow;
- alerts.

## 7. Branding direction

Name: ReLead Ops

Positioning:

```text
A secure operations control plane for ReLead infrastructure, SSH targets, Codespaces and deployment automation.
```

Visual idea:

- dark interface;
- electric blue / cyan accent;
- terminal-inspired typography for technical areas;
- shield + command prompt + network nodes as logo motif.
