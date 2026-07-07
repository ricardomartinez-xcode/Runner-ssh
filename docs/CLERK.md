# Clerk + Runner SSH

The Runner is an OAuth/OIDC resource server. It does not need the Clerk SDK: it verifies signed JWT access tokens against the issuer JWKS using `jose`.

## 1. Configure Clerk as the OAuth provider

Create an OAuth application in Clerk for the GPT Action. Use the callback URL shown by the GPT editor exactly. For this Runner, use a Clerk custom domain under `relead.com.mx` (for example `auth.relead.com.mx`) so the Action API and OAuth endpoints share the same root domain.

Configure the OAuth application to issue access tokens as JWTs. The Runner cannot validate opaque access tokens locally.

## 2. Configure token claims

The OAuth access token must contain:

- `sub`: stable Clerk user ID.
- `aud`: `runner-api` (or the value chosen for `OIDC_AUDIENCE`).
- `scope` or `scp`: `runner:ssh`.
- A role that matches `RUNNER_VIEWER_ROLE` or `RUNNER_OPERATOR_ROLE`.

By default, the Runner reads generic roles from `roles` and `org_role`, plus the existing Keycloak `realm_access.roles` and `resource_access.*.roles` structures. Change `OIDC_ROLE_CLAIMS` to a comma-separated list of claim paths when your Clerk token uses another claim, for example `public_metadata.runner_roles,org_role`.

## 3. Configure Render

Set these environment variables in Render after obtaining the Clerk issuer metadata:

```text
AUTH_MODE=dual
OIDC_ISSUER_URL=<Clerk issuer>
OIDC_JWKS_URL=<Clerk JWKS URL>
OIDC_AUDIENCE=runner-api
OIDC_REQUIRED_SCOPE=runner:ssh
OIDC_ROLE_CLAIMS=roles,org_role
RUNNER_API_TOKEN_SHA256=<optional static token SHA-256>
RUNNER_API_TOKEN_ROLES=runner.operator
```

`AUTH_MODE=oidc` accepts only signed OIDC JWTs. `AUTH_MODE=api_token` accepts only the configured static Bearer token. `AUTH_MODE=dual` accepts either one and is the recommended migration mode.

## 4. Configure GPT Actions

For user sign-in, configure OAuth with Clerk's authorization and token endpoints, client ID, client secret, and scope `openid runner:ssh`.

For an emergency or machine-only integration, configure the Action with API key / Bearer authentication and use the raw static token. The Runner stores only its SHA-256 digest; rotate the raw token by replacing the digest in Render and updating the Action.

Never commit the raw token, Clerk secret key, OAuth client secret, authorization code, cookies, or JWTs.
