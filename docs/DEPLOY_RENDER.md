# Render deployment

`render.yaml` is included with `autoDeploy: false`; nothing is deployed by this repository.

Before deployment:

1. Replace all placeholders in `config/runner.yaml`.
2. Set actual pinned host keys for each SSH target.
3. Configure Supabase Auth and profiles. The production JWT issuer is `https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1`.
4. Keep these public JWT settings in Render:
   - `SUPABASE_URL=https://hmhmhpyksqufclqzjkxo.supabase.co`
   - `SUPABASE_JWKS_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1/.well-known/jwks.json`
   - `OIDC_ISSUER_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1`
   - `OIDC_JWKS_URL=https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1/.well-known/jwks.json`
   - `OIDC_AUDIENCE=authenticated`
5. Add `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `SSH_KEY_ENCRYPTION_SECRET`, `RUNNER_API_TOKEN_SHA256` and `OP_SERVICE_ACCOUNT_TOKEN` as Render secret values.
6. Use a paid web service with a persistent disk for the file-backed job store.
7. Assign a custom HTTPS domain, then replace the placeholder server in `openapi/gpt-actions.yaml`.
8. Test OAuth and a read-only task against staging before adding a production target.

No private key, password, GitHub token or 1Password service account token belongs in Git.
