# Cloudflare Production

Current production entry:

```text
runner.relead.com.mx
```

Requested operations alias:

```text
ops.relead.com.mx
```

Both hostnames must point to the same `relead-ops-web` Render service and the same canonical panel at `/admin/manage`. Do not deploy a second panel or a second application. Keep `/admin` and `/admin/manage-v2` only as compatibility redirects.

## DNS

1. Keep `runner.relead.com.mx` attached to `relead-ops-web` and, when desired, add `ops.relead.com.mx` to that same service.
2. Add the DNS record in Cloudflare exactly as Render specifies.
3. Keep proxy enabled unless Render validation requires a temporary DNS-only check.

## Security Controls

Recommended Cloudflare controls:

- HTTPS only.
- WAF managed rules.
- Bot fight or equivalent bot protections.
- Rate limiting for `/admin/*` and `/admin/api/*`.
- Optional Cloudflare Access in front of the whole panel.
- `X-Robots-Tag: noindex` is also emitted by the app for admin routes.

## Suggested Rate Limits

- `/admin/api/executions/*/confirm`: low threshold by user/IP.
- `/admin/api/executions/*/approve`: admin-only, low threshold.
- `/admin/api/v2/targets/*/test-connection`: low threshold to avoid queue abuse; SSH itself runs only in the worker.
- `/admin/config`: moderate threshold.

## Headers

The app emits:

- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` for admin routes
- `X-Robots-Tag: noindex, nofollow` for admin routes

## Cloudflare Access

Cloudflare Access is optional but recommended for production. If enabled, keep Supabase Auth too. Access is an outer gate; it must not replace application authorization.

## SSH Through Cloudflare Tunnel

ReLead Ops supports only these executable target types:

- `ssh`: direct OpenSSH from the worker to a reachable host.
- `cloudflare_tunnel`: SSH through Cloudflare Tunnel using client-side `cloudflared`.

For `cloudflare_tunnel` targets, the Render worker image includes `cloudflared` and runs SSH with:

```text
ProxyCommand=cloudflared access ssh --hostname %h
```

For a non-interactive Render web or worker process behind Cloudflare Access, configure these Render secrets:

```env
TUNNEL_SERVICE_TOKEN_ID=
TUNNEL_SERVICE_TOKEN_SECRET=
```

`cloudflared access ssh` reads those values from the process environment, equivalent to passing `--service-token-id` and `--service-token-secret`. Do not put service token values in Git, target metadata or logs.

Required production setup:

1. Install and authenticate `cloudflared` on the target host.
2. Create a named tunnel, for example `relead`.
3. Route a public hostname such as `ssh.relead.com.mx` to the target's local SSH service, for example `ssh://localhost:2222`.
4. Configure Cloudflare Access for the hostname. For non-interactive Render workers, prefer a service-token policy or another automation-safe Access method; browser login is not suitable for the worker.
5. Capture `known_hosts` for the hostname and store that exact line on the target record.
6. Store SSH credentials as a managed encrypted ReLead Ops credential or a Render secret.

Do not expose the host's public SSH port and do not disable `StrictHostKeyChecking`.

On the target host, a Cloudflare-managed tunnel token can be installed with:

```bash
sudo cloudflared service install '<CLOUDFLARE_TUNNEL_TOKEN>'
```

Do not commit the tunnel token. After installation, verify:

```bash
systemctl status cloudflared --no-pager
journalctl -u cloudflared -n 100 --no-pager
```

## Protect `/bash`

Create a separate self-hosted Cloudflare Access application for the `/bash` path and all child paths, including `/bash/socket`. Use an exact owner identity, require MFA, keep the policy deny-by-default and do not add a Bypass rule. Configure the application AUD and team domain in `CLOUDFLARE_ACCESS_AUD` and `CLOUDFLARE_ACCESS_TEAM_DOMAIN`.

The origin validates every `Cf-Access-Jwt-Assertion` against the account JWKS and expected AUD. This prevents direct access through the Render origin hostname from bypassing Cloudflare Access. The recovery key remains a second, independent factor. Full setup and revocation are documented in `docs/BREAK_GLASS.md`.
