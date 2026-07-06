# Render deployment

`render.yaml` is included with `autoDeploy: false`; nothing is deployed by this repository.

Before deployment:

1. Replace all placeholders in `config/runner.yaml`.
2. Set actual pinned host keys for each SSH target.
3. Create the Keycloak client and roles described in `KEYCLOAK.md`.
4. Add `OIDC_ISSUER_URL`, `OIDC_JWKS_URL`, `OIDC_AUDIENCE` and `OP_SERVICE_ACCOUNT_TOKEN` as Render secrets.
5. Use a paid web service with a persistent disk for the file-backed job store.
6. Assign a custom HTTPS domain, then replace the placeholder server in `openapi/gpt-actions.yaml`.
7. Test OAuth and a read-only task against staging before adding a production target.

No private key, password, GitHub token or 1Password service account token belongs in Git.
