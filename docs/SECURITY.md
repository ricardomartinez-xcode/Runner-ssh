# Security Model

ReLead Ops is a catalog-driven runner, not a remote shell.

## Guarantees

- Commands execute only from `commands` assigned through `target_commands`.
- Users must have the right role and an authenticated Supabase session.
- High-risk and destructive commands require admin approval.
- Every execution keeps `requested_by`, confirmation, approval/rejection state, worker metadata, logs and audit records.
- SSH uses pinned `known_hosts` and `StrictHostKeyChecking=yes`.
- Credentials never return to the browser.
- Managed credentials are encrypted with AES-256-GCM and a Render-only `SSH_KEY_ENCRYPTION_SECRET`.
- Logs are redacted and truncated before persistence.
- Web has security headers, CSP, clickjacking protection, no-cache admin pages and in-memory rate limiting. Cloudflare should enforce external WAF/rate limits.

## Forbidden Patterns

- Do not add `ssh.exec` or raw command endpoints.
- Do not accept arbitrary commands from GPT Actions, users or query strings.
- Do not set `StrictHostKeyChecking=no`.
- Do not commit private keys, passwords, Supabase service role keys, Tailscale auth keys or OAuth secrets.
- Do not expose laptops directly to the public internet.
- Do not rely on frontend checks for authorization.

## Worker Boundary

The worker has no inbound HTTP API. It uses the Supabase service role key to call RPC functions and update rows. Internal web-worker endpoints are therefore avoided instead of protected by a shared HTTP token.

## Credential Rotation

1. Add the new credential as a managed credential or Render secret.
2. Test connection from the target detail view.
3. Disable the old credential on the target.
4. Remove old public keys from the target.
5. Verify audit logs for `target.updated` and `target.connection_tested`.

## Target Revocation

1. Disable the target in ReLead Ops.
2. Remove its public key from `authorized_keys`.
3. Delete or rotate Render secret variables.
4. Delete the target after logs/audit are reviewed.
