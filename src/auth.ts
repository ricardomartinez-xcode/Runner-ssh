import { createHash, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Environment } from "./config.js";
import type { Principal } from "./types.js";
import { unauthorized } from "./errors.js";

export interface Authenticator {
  verify(header: string | undefined): Promise<Principal>;
}

function scopeValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  if (typeof value === "string") return value.split(/\s+/).filter(Boolean);
  return [];
}

function roleValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  if (typeof value === "string") return value.split(/[\s,]+/).filter(Boolean);
  return [];
}

function csvValues(value: string | undefined): string[] {
  if (!value) return [];
  return [...new Set(value.split(",").map((entry) => entry.trim()).filter(Boolean))].sort();
}

function claim(payload: JWTPayload, path: string): unknown {
  let current: unknown = payload;
  for (const segment of path.split(".").map((entry) => entry.trim()).filter(Boolean)) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function roles(payload: JWTPayload, configuredClaims: string): string[] {
  const result = new Set<string>();

  const realm = payload.realm_access;
  if (realm && typeof realm === "object" && "roles" in realm) {
    roleValues((realm as Record<string, unknown>).roles).forEach((role) => result.add(role));
  }

  const resource = payload.resource_access;
  if (resource && typeof resource === "object") {
    Object.values(resource as Record<string, unknown>).forEach((entry) => {
      if (entry && typeof entry === "object" && "roles" in entry) {
        roleValues((entry as Record<string, unknown>).roles).forEach((role) => result.add(role));
      }
    });
  }

  csvValues(configuredClaims).forEach((path) => {
    roleValues(claim(payload, path)).forEach((role) => result.add(role));
  });

  return [...result].sort();
}

function bearerToken(header: string | undefined): string {
  if (!header?.startsWith("Bearer ")) {
    throw unauthorized("A Bearer access token is required.");
  }

  const token = header.slice(7).trim();
  if (!token) throw unauthorized("A Bearer access token is required.");
  return token;
}

function matchesSha256(token: string, expectedHex: string | undefined): boolean {
  if (!expectedHex) return false;
  const actual = createHash("sha256").update(token, "utf8").digest();
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export class Auth implements Authenticator {
  private readonly jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly env: Environment) {
    if (env.AUTH_MODE !== "api_token") {
      this.jwks = createRemoteJWKSet(new URL(env.OIDC_JWKS_URL!));
    }
  }

  async verify(header: string | undefined): Promise<Principal> {
    const token = bearerToken(header);

    if (this.env.AUTH_MODE !== "oidc" && matchesSha256(token, this.env.RUNNER_API_TOKEN_SHA256)) {
      return {
        subject: "runner-api-token",
        roles: csvValues(this.env.RUNNER_API_TOKEN_ROLES),
        scopes: [this.env.OIDC_REQUIRED_SCOPE],
      };
    }

    if (this.env.AUTH_MODE === "api_token") {
      throw unauthorized("Access token validation failed.");
    }

    return this.verifyOidc(token);
  }

  private async verifyOidc(token: string): Promise<Principal> {
    const issuer = this.env.OIDC_ISSUER_URL;
    const audience = this.env.OIDC_AUDIENCE;
    if (!this.jwks || !issuer || !audience) {
      throw unauthorized("OIDC authentication is not configured.");
    }

    try {
      const { payload } = await jwtVerify(token, this.jwks, { issuer, audience });

      if (typeof payload.sub !== "string" || !payload.sub) {
        throw unauthorized("Access token is missing subject.");
      }

      const scopes = [...new Set([...scopeValues(payload.scope), ...scopeValues(payload.scp)])].sort();
      if (!scopes.includes(this.env.OIDC_REQUIRED_SCOPE)) {
        throw unauthorized(`Access token is missing scope "${this.env.OIDC_REQUIRED_SCOPE}".`);
      }

      return {
        subject: payload.sub,
        roles: roles(payload, this.env.OIDC_ROLE_CLAIMS),
        scopes,
      };
    } catch (error) {
      if (error instanceof Error && error.name === "AppError") throw error;
      throw unauthorized("Access token validation failed.");
    }
  }
}
