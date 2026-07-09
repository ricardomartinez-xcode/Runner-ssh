# ReLead Ops

Secure operations control plane for ReLead infrastructure, SSH targets, GitHub Codespaces and deployment automation.

ReLead Ops evolves the original Runner SSH into an admin platform backed by Supabase and deployable on Render.

It can run configured, allowlisted tasks on:

- existing servers or laptops through SSH;
- GitHub Codespaces through `gh codespace ssh`;
- future Tailscale and Cloudflare Tunnel targets;
- future deployment and infrastructure integrations.

It is not a generic remote shell.

## Safety boundary

Commands remain allowlisted and require explicit confirmation before execution:

```text
list -> plan -> explicit EJECUTAR -> execute -> read redacted log
```

GPT Actions, users or external clients cannot submit arbitrary hostnames, usernames, passwords, private keys or raw commands. Production configuration defines the allowed targets, commands and permissions.

## Supabase-powered admin layer

The ReLead Ops admin layer uses Supabase for:

- Supabase Auth;
- profiles and roles;
- targets;
- commands;
- executions;
- health checks;
- audit logs;
- realtime dashboard events.

Apply the initial schema from:

```text
supabase/migrations/0001_runner_admin.sql
```

Production rollout guide:

```text
docs/RELEAD_OPS_PRODUCTION.md
```

## Authentication modes

The current runner API still supports:

- `oidc` — signed OIDC access tokens only;
- `api_token` — static Bearer token hash only;
- `dual` — accepts either OIDC JWTs or the static Bearer token;
- `clerk_oauth` — legacy Clerk migration mode.

For the new Admin UI, prefer Supabase Auth. Clerk should be treated as deprecated for this project.

## Local verification

```bash
cp .env.example .env
npm install --include=prod --include=dev
npm run check
npm test
```

## Deployment

Render Blueprint is included in `render.yaml`.

Recommended service name:

```text
relead-ops-api
```

Recommended domain:

```text
ops.relead.com.mx
```

Required production variables are listed in `docs/RELEAD_OPS_PRODUCTION.md`.

## Branding

Name: **ReLead Ops**

Positioning:

```text
A secure operations control plane for ReLead infrastructure, SSH targets, Codespaces and deployment automation.
```

Suggested visual system:

- dark admin interface;
- cyan/electric blue accent;
- shield + terminal prompt + connected nodes;
- technical but clean typography.
