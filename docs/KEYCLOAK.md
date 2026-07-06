# Keycloak OAuth and GPT Actions

The runner is an OIDC **resource server**. Keycloak handles the OAuth authorization-code flow configured in the GPT Actions editor; this API receives and validates the resulting Bearer access token.

## Keycloak client

Create a confidential client for this runner.

- Client ID: `runner-ssh-api`
- Standard flow: enabled
- Direct access grants: disabled
- Valid redirect URI: paste the exact callback displayed by the GPT Actions editor
- Audience mapper: add `runner-ssh-api`
- Client scope: `runner:ssh`

Create and assign these realm roles:

- `runner.viewer`: list collections/targets and read own jobs/logs.
- `runner.operator`: plan, confirm and cancel configured tasks.

## GPT Actions fields

- Authentication: OAuth
- Authorization URL: `<issuer>/protocol/openid-connect/auth`
- Token URL: `<issuer>/protocol/openid-connect/token`
- Scope: `openid profile email runner:ssh`
- Client ID / secret: Keycloak client credentials
- Callback: exact value shown in the GPT Actions editor

## Runner variables

```text
OIDC_ISSUER_URL=https://keycloak.example.com/realms/runner
OIDC_JWKS_URL=https://keycloak.example.com/realms/runner/protocol/openid-connect/certs
OIDC_AUDIENCE=runner-ssh-api
OIDC_REQUIRED_SCOPE=runner:ssh
```
