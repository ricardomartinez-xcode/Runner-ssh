# Security Model

ReLead Ops is a catalog-driven runner, not a remote shell.

## Guarantees

- Commands execute only from `commands` assigned through `target_commands`.
- Executable targets are limited to `ssh` and `cloudflare_tunnel`.
- Users must have the right role and an authenticated Supabase session.
- High-risk and destructive commands require admin approval.
- Every execution keeps `requested_by`, confirmation, approval/rejection state, worker metadata, logs and audit records.
- SSH uses pinned `known_hosts` and `StrictHostKeyChecking=yes`.
- Credentials never return to the browser.
- Browser Supabase sessions are read-only; audited mutations and worker RPC functions require the backend service role.
- The admin access token uses tab-scoped `sessionStorage` and expires with the Supabase JWT; no refresh token or service-role key is stored in the browser.
- Managed credentials are encrypted with AES-256-GCM and a Render-only `SSH_KEY_ENCRYPTION_SECRET`.
- Logs are redacted and truncated before persistence.
- Web has security headers, CSP, clickjacking protection, no-cache admin pages and in-memory rate limiting. Cloudflare should enforce external WAF/rate limits.
- Supabase JWT verification uses the public JWKS endpoint `https://hmhmhpyksqufclqzjkxo.supabase.co/auth/v1/.well-known/jwks.json` and expects key id `41cd089a-c0fc-44fe-bc70-d71fb746a16f` for the current `ES256` signing key.
- `/bash` is an explicit break-glass exception: it is independent from Supabase roles and proxies a full SSH terminal to the Render worker only after Cloudflare Access and recovery-key authentication.

## Forbidden Patterns

- Do not add `ssh.exec` or raw command endpoints.
- Do not accept arbitrary commands from GPT Actions, users or query strings.
- Force every command created outside the reviewed catalog to high risk, admin-only execution and runtime approval.
- Do not set `StrictHostKeyChecking=no`.
- Do not commit private keys, passwords, Supabase service role keys, Tailscale auth keys or OAuth secrets.
- Do not expose laptops directly to the public internet.
- Do not rely on frontend checks for authorization.
- Do not enable `/bash` without path-specific Cloudflare Access, an offline recovery key, a dedicated Render SSH key, strict Render `known_hosts`, short sessions and a tested revocation procedure.

## Worker Boundary

The worker has no inbound HTTP API. It uses the Supabase service role key to call RPC functions and update rows. Internal web-worker endpoints are therefore avoided instead of protected by a shared HTTP token.

The worker writes non-secret liveness metadata to `worker_instances`. The break-glass console does not execute a second local command runner: it proxies OpenSSH with `shell:false` to Render's official SSH endpoint. Authentication failures, session open/close, byte counts and stream digests are written to the web persistent disk and mirrored to Supabase. Plain terminal contents are not retained because they can contain secrets.

## Credential Rotation

1. Add the new credential as a managed credential or Render secret.
2. Test connection from the target detail view.
   The web process only queues `target_connection_tests`; SSH runs in `relead-ops-worker` and an onboarding target is enabled only after success.
3. Disable the old credential on the target.
4. Remove old public keys from the target.
5. Verify audit logs for `target.updated` and `target.connection_tested`.

## Target Revocation

1. Disable the target in ReLead Ops.
2. Remove its public key from `authorized_keys`.
3. Delete or rotate Render secret variables.
4. Delete the target after logs/audit are reviewed.
