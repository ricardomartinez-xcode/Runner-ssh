# Runner SSH

OAuth-protected, **allowlisted** SSH task runner for GPT Actions.

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

## Local verification

```bash
cp .env.example .env
# Fill OIDC variables and replace config placeholders.
npm install
npm run check
npm test
```

## OAuth and 1Password

- Keycloak instructions: [docs/KEYCLOAK.md](docs/KEYCLOAK.md)
- 1Password Service Account references remain server-side in `config/runner.yaml`.
- Never commit `OP_SERVICE_ACCOUNT_TOKEN`, GitHub tokens, passwords or private keys.

## GPT Action schema

Import [openapi/gpt-actions.yaml](openapi/gpt-actions.yaml), change the server URL to the final HTTPS runner domain, then configure OAuth in the GPT Actions editor.

Available actions: `listSshCollections`, `getSshCollection`, `listSshTargets`, `getSshTarget`, `planSshTask`, `confirmSshJob`, `getSshJob`, `getSshJobLog`, `cancelSshJob`.

## Deployment

Render Blueprint is included, but `autoDeploy: false` is set. See [docs/DEPLOY_RENDER.md](docs/DEPLOY_RENDER.md).
