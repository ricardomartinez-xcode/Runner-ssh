# Cloudflare Production

Domain:

```text
ops.relead.com.mx
```

## DNS

1. Create the Render custom domain for `relead-ops-web`.
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
- `/admin/api/v2/test-connection`: low threshold to avoid SSH probing.
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
