# Clerk + Runner SSH

The Runner supports two Clerk-compatible patterns:

1. `AUTH_MODE=oidc` for locally verified JWT access tokens using issuer/JWKS/audience.
2. `AUTH_MODE=clerk_oauth` for Clerk OAuth access tokens validated through Clerk's `/oauth/token_info` endpoint.

`clerk_oauth` is the recommended mode for GPT Actions because Clerk's OAuth applications do not expose a custom claims editor like JWT Templates. JWT Templates are generated with Clerk session helpers such as `getToken({ template })`, while GPT Actions receive the normal OAuth access token from the OAuth code exchange.

## 1. Configure Clerk as the OAuth provider

Create an OAuth application in Clerk for the GPT Action.

Use the callback URL shown by the GPT editor. For this Runner, keep both variants when available:

```text
https://chat.openai.com/aip/<gpt-id>/oauth/callback
https://chatgpt.com/aip/<gpt-id>/oauth/callback
```

Use a Clerk custom domain under the same root domain as the Runner API, for example:

```text
https://clerk.runner.relead.com.mx
```

The GPT Action API server remains:

```text
https://runner.relead.com.mx
```

## 2. Configure GPT Actions

Use OAuth authentication:

```text
Client ID: <Clerk OAuth Application Client ID>
Client Secret: <Clerk OAuth Application Client Secret>
Authorization URL: https://clerk.runner.relead.com.mx/oauth/authorize
Token URL: https://clerk.runner.relead.com.mx/oauth/token
Scope: openid email profile
Token Exchange Method: Default
```

The OpenAPI `servers` entry must point to the Runner, not Clerk:

```yaml
servers:
  - url: https://runner.relead.com.mx
```

## 3. Configure Render with native Clerk OAuth validation

For a single private GPT user, use the user's email as the role value:

```text
AUTH_MODE=clerk_oauth
CLERK_FRONTEND_API_URL=https://clerk.runner.relead.com.mx
CLERK_OAUTH_CLIENT_ID=<Clerk OAuth Application Client ID>
CLERK_OAUTH_CLIENT_SECRET=<Clerk OAuth Application Client Secret>
CLERK_REQUIRED_SCOPE=email
CLERK_ROLE_CLAIMS=email
RUNNER_VIEWER_ROLE=ricardomartinez@relead.com.mx
RUNNER_OPERATOR_ROLE=ricardomartinez@relead.com.mx
```

`CLERK_OAUTH_CLIENT_SECRET` belongs in Render only. Do not commit it.

The Runner validates the access token by:

1. Calling Clerk `/oauth/token_info` with Basic auth using the OAuth client credentials.
2. Ensuring the token is active and belongs to `CLERK_OAUTH_CLIENT_ID`.
3. Checking `CLERK_REQUIRED_SCOPE`.
4. Calling `/oauth/userinfo` and reading role values from `CLERK_ROLE_CLAIMS`.

## 4. Optional JWT-only mode

Use `AUTH_MODE=oidc` only when you know the OAuth access token is a JWT and you know its exact `aud` claim:

```text
AUTH_MODE=oidc
OIDC_ISSUER_URL=https://clerk.runner.relead.com.mx
OIDC_JWKS_URL=https://clerk.runner.relead.com.mx/.well-known/jwks.json
OIDC_AUDIENCE=<exact aud claim>
OIDC_REQUIRED_SCOPE=email
OIDC_ROLE_CLAIMS=email
RUNNER_VIEWER_ROLE=ricardomartinez@relead.com.mx
RUNNER_OPERATOR_ROLE=ricardomartinez@relead.com.mx
```

If the Runner returns `Access token validation failed`, prefer `AUTH_MODE=clerk_oauth`.
