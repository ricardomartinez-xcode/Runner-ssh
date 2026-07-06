import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Environm } from "./config.js";
import type { Principal } from "./types.js";
import { unauthorized } from "./errors.js";

function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  return [];
}

function roles(payload: JWTPayload): string[] {
  const result = new Set<string>();
  const realm = payload.realm_access;
  if (realm && typeof realm === "object" && "roles" in realm) {
    strings((realm as Record<string, unknown>).roles).forEach((role) => result.add(role));
  }
  const resource = payload.resource_access;
  if (resource && typeof resource === "object") {
    Object.values(resource as Record<string, unknown>).forEach((entry) => {
      if (entry && typeof entry === "object" && "roles" in entry) {
        strings((entry as Record<string, unknown>).roles).forEach((role) => result.add(role));
      }
    });
  }
  return [...result].sort();
}

export class OidcAuth {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly env: Environment) {
    this.jwks = createRemoteJWKSet(new URL(env.OIDC_JWKS_URL));
  }

  async verify(header: string | undefined): Promise<Principal> {
    if (!header?.startsWith("Bearer ")) throw unauthorized("A Bearer access token is required.");
    const token = header.slice(7).trim();
    if (!token) throw unauthorized("A Bearer access token is required.");

    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        issuer: this.env.OIDC_ISSUER_URL,
        audience: this.env.OIDC_AUDIENCE,
      });
      if (typeof payload.sub !== "string" || !payload.sub) throw unauthorized("Access token is missing subject.");
      const scopes = [...new Set([...strings(payload.scope), ...strings(payload.scp)])].sort();
      if (!scopes.includes(this.env.OIDC_REQUIRED_SCOPE)) {
        throw unauthorized(`Access token is missing scope "${this.env.OIDC_REQUIRED_SCOPE}".`);
      }
      return { subject: payload.sub, roles: roles(payload), scopes };
    } catch (error) {
      if (error instanceof Error && error.name === "AppError") throw error;
      throw unauthorized("Access token validation failed.");
    }
  }
}
