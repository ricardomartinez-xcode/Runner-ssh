# Runner SSH

OIDC/OAuth-protected, **allowlisted** SSH task runner for GPT Actions. It also supports a separately configured static Bearer token for controlled machine access or an OAuth migration.

It can run configured tasks on:

- an existing server or laptop through SSH;
- an already-running GitHub Codespace through `gh codespace ssh`.

It is not a generic remote shell.

## Safety boundary

GPT Actions cannot submit a command, host, port, username, password, private key or 1Password reference. The deployment configuration defines every target and fixed task:

```text
list -> plan -> explicit EJECUTAR -> execute -> read redacted log
```

The included task collections are:

- `repository`: `repo.status`, `repo.lint`, `repo.typecheck`, `repo.test`, `repo.build`
- `system`: `system.info`, `service.status`, `docker.ps`

System tasks invoke a target-local `/usr/local/bin/runner-task` wrapper. See [docs/SECURITY.md](docs/SECURITY.md).

## Authentication modes

The Runner always expects an `Authorization: Bearer <token>` header. Set `AUTH_MODE` in Render:

- `oidc` — signed OIDC access tokens only; default.
- `api_token` — static Bearer token only. The server stores only `RUNNER_API_TOKEN_SHA256`.
- `dual` — accepts either a static Bearer token or a signed OIDC access token. Use this for migration.

OIDC remains provider-agnostic. The verifier checks issuer, JWKS signature, audience, required scope and roles. It supports Keycloak role claims plus generic configurable claims such as Clerk's `roles` or `org_role`. See [docs/CLERK.md](docs/CLERK.md).

## Local verification

```bash
cp .env.example .env
# Fill OIDC variables or choose AUTH_MODE=api_token and configure the token digest.
npm install --include=prod --include=dev
npm run check
npm test
```

## OAuth, static Bearer tokens, and 1Password

- Configure the OAuth browser flow in the GPT Actions editor.
- For Clerk, configure an OAuth application that issues signed JWT access tokens and use [docs/CLERK.md](docs/CLERK.md).
- For static Bearer mode, generate the raw token outside the repository, hash it with SHA-256, and store only `RUNNER_API_TOKEN_SHA256` in Render. The raw token goes only in the GPT Action API-key configuration.
- 1Password Service Account references remain server-side in `config/runner.yaml`.
- Never commit `OP_SERVICE_ACCOUNT_TOKEN`, raw static tokens, OAuth client secrets, GitHub tokens, passwords or private keys.

## GPT Action schema

Import [openapi/gpt-actions.yaml](openapi/gpt-actions.yaml), change the server URL to the final HTTPS Runner domain, then configure OAuth or Bearer API-key authentication in the GPT Actions editor.

Available actions: `listSshCollections`, `getSshCollection`, `listSshTargets`, `getSshTarget`, `planSshTask`, `confirmSshJob`, `getSshJob`, `getSshJobLog`, `cancelSshJob`.

## Deployment

Render Blueprint is included, but `autoDeploy: false` is set. See [docs/DEPLOY_RENDER.md](docs/DEPLOY_RENDER.md).
