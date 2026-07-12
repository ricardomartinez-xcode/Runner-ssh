# Break-Glass Recovery Console

`/bash` is an independent recovery surface for the `relead-ops-worker` container. It is intentionally outside Supabase roles, the command catalog, `EJECUTAR`, approvals and target permissions. After recovery authentication, the browser receives an interactive shell with the same application-user access as Render's native SSH session.

## Architecture

```text
browser
  -> Cloudflare Access for runner.relead.com.mx/bash*
  -> recovery-key verification in relead-ops-web
  -> short-lived HttpOnly, SameSite=Strict, Access-identity-bound session
  -> one-use in-memory WebSocket ticket
  -> WebSocket terminal
  -> OpenSSH with dedicated key and pinned Render host key
  -> Render SSH endpoint
  -> relead-ops-worker container as user runner
```

The web service does not run arbitrary commands locally. It forwards terminal bytes to Render's official SSH endpoint with `shell:false`, `BatchMode=yes`, `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes` and password authentication disabled.

## Security Consequence

This is full application-container control, not a normal ReLead Ops execution. The shell can inspect the worker filesystem, processes and environment, including production credentials available to that worker. Treat compromise of either the recovery key or `BREAK_GLASS_RENDER_PRIVATE_KEY` as a production incident.

Render attaches SSH public keys to an account, not to a single service. The corresponding private key can therefore reach every SSH-compatible service that account is authorized to access. Use a dedicated Render identity and, for strict isolation, a dedicated workspace containing only the recovery worker. Do not reuse an administrator's personal Render key.

The container continues to run as the unprivileged `runner` user. `/bash` does not enable root login, `sudo`, an SSH daemon inside the image, or password authentication.

## Required Variables

Configure these only on `relead-ops-web`:

```env
BREAK_GLASS_ENABLED=false
BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS=true
BREAK_GLASS_KEY_SHA256=
BREAK_GLASS_SESSION_SECRET=
BREAK_GLASS_SESSION_TTL_SECONDS=600
BREAK_GLASS_MAX_SESSION_BYTES=16777216
BREAK_GLASS_MAX_FAILED_ATTEMPTS=5
BREAK_GLASS_LOCKOUT_SECONDS=900
BREAK_GLASS_RENDER_PRIVATE_KEY=
BREAK_GLASS_RENDER_SERVICE_ID=
BREAK_GLASS_RENDER_SSH_HOST=
BREAK_GLASS_RENDER_KNOWN_HOSTS=
CLOUDFLARE_ACCESS_TEAM_DOMAIN=https://YOUR-TEAM.cloudflareaccess.com
CLOUDFLARE_ACCESS_AUD=
```

Keep `BREAK_GLASS_ENABLED=false` until every value and both authentication layers have been tested.

The one-use socket ticket is kept in web-process memory. Keep the recovery web service at one instance; scaling it horizontally requires a shared, atomic ticket store before `/bash` can remain enabled.

## Create Dedicated Credentials

Generate a dedicated Ed25519 key. Do not reuse a target key or a personal default key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/relead_ops_render_break_glass_ed25519 -C relead-ops-render-break-glass
```

Add only the `.pub` value under Render Account Settings > SSH Public Keys for the dedicated recovery identity. Store the private key as `BREAK_GLASS_RENDER_PRIVATE_KEY` on the web service. Render must never receive the recovery key itself. Because Render account keys are not service-scoped, limit that identity's workspace access before enabling `/bash`.

Generate and hash the separate recovery key:

```bash
RECOVERY_KEY="$(openssl rand -base64 48)"
printf %s "$RECOVERY_KEY" | openssl dgst -sha256 -hex
openssl rand -base64 48
```

Store the digest from the second command as `BREAK_GLASS_KEY_SHA256`. Store the last command's value as `BREAK_GLASS_SESSION_SECRET`. Keep the raw `RECOVERY_KEY` offline in a protected recovery record.

## Render SSH Values

Open the worker's Render dashboard and select Connect > SSH. Use the service ID from the SSH username as `BREAK_GLASS_RENDER_SERVICE_ID` and the regional hostname as `BREAK_GLASS_RENDER_SSH_HOST`. A specific instance can be selected by using Render's documented instance suffix.

Copy the matching official Render `known_hosts` line into `BREAK_GLASS_RENDER_KNOWN_HOSTS` only after comparing its fingerprint with Render's published fingerprint. Never use `StrictHostKeyChecking=no` and never populate this value with `ssh-keyscan` alone.

The Docker image gives the non-root `runner` user `/bin/bash` and a mode-0700 `~/.ssh` directory, which Render requires for Docker service shell access. It does not start `sshd`.

## Cloudflare Access

Create a self-hosted Access application covering `/bash` and all `/bash/*` routes. The policy should:

- include only the recovery owner identity;
- require MFA and, when available, a managed-device posture check;
- use a session duration no longer than the ReLead recovery session;
- have no Bypass rule;
- protect WebSocket traffic to `/bash/socket`;
- leave the application deny-by-default.

Set the application's AUD and the full team-domain URL in Render. The origin verifies `Cf-Access-Jwt-Assertion`; reaching the Render origin directly does not bypass this check.

## Enable And Test

1. Deploy with `BREAK_GLASS_ENABLED=false` so the Docker shell prerequisites are present.
2. Confirm native access with Render Dashboard Shell or `render ssh <service-id>` using the dedicated key.
3. Configure Cloudflare Access and all web-service variables.
4. Set `BREAK_GLASS_ENABLED=true` and redeploy only `relead-ops-web`.
5. Open `https://runner.relead.com.mx/bash`, authenticate through Access and enter the recovery key.
6. Run `id`, `pwd`, `ps aux`, `df -h` and `node --version`.
7. Select `Bloquear` and verify the audit records.

## Audit

The web service requires a persistent disk and writes append-only JSON lines to:

```text
/var/data/break-glass-audit.jsonl
```

It also mirrors events to `audit_logs` when Supabase is available. Events include failed authentication, session authentication, SSH open/close, byte counts and keyed HMAC-SHA-256 stream digests. Each local JSON record also carries an HMAC for tamper detection. Terminal plaintext is deliberately not persisted because repair commands and output can contain secrets. Input and output are each bounded by `BREAK_GLASS_MAX_SESSION_BYTES`; reaching the limit terminates the session and records the reason.

## Revoke Access

1. Set `BREAK_GLASS_ENABLED=false` and redeploy the web service.
2. Remove the dedicated public key from the Render account.
3. Rotate `BREAK_GLASS_SESSION_SECRET` to invalidate every outstanding cookie.
4. Generate a new recovery key and replace only its SHA-256 digest if the key may have leaked.
5. Rotate worker secrets if an unauthorized shell session may have occurred.
6. Review the local audit file, Supabase audit mirror, Cloudflare Access logs and Render account activity.

## Recovery And Troubleshooting

- `403 access_required`: the request did not carry a valid Cloudflare Access JWT for the configured AUD.
- `401 recovery_denied`: the recovery key does not match its configured SHA-256 digest.
- `423 recovery_locked`: too many failed keys for the same validated Access identity; wait for the lockout or redeploy after confirming the source.
- WebSocket code `1008`: the one-use socket ticket was missing, expired or already consumed; enter the recovery key again.
- WebSocket code `1009`: the configured session input/output byte limit was reached; open a new authenticated session after checking the command that produced excessive output.
- SSH permission denied: verify the dedicated public key is attached to the correct Render account and the service is on a paid SSH-compatible plan.
- Host-key error: compare the regional Render fingerprint and replace the pinned entry only after independent verification.
- Web service unavailable: use Render Dashboard Shell or `render ssh <service-id>` directly. Native Render access is the final recovery path and does not depend on ReLead Ops, Supabase or Cloudflare.
