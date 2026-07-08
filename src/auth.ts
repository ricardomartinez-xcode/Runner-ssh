import { createHash, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Environment } from "./config.js";
import type { Principal } from "./types.js";
import { unauthorized } from "./errors.js";

export interface Authenticator {
  verify(header: string | undefined): Promise<Principal>;
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
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

function claim(payload: JsonRecord | JWTPayload, path: string): unknown {
  let current: unknown = payload;
  for (const segment of path.split(".").map((entry) => entry.trim()).filter(Boolean)) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return current;
}

function configuredRoles(payload: JsonRecord | JWTPayload, configuredClaims: string): string[] {
  const result = new Set<string>();

  csvValues(configuredClaims).forEach((path) => {
    roleValues(claim(payload, path)).forEach((role) => result.add(role));
  });

  return [...result].sort();
}

function oidcRoles(payload: JWTPayload, configuredClaims: string): string[] {
  const result = new Set<string>();

  const realm = payload.realm_access;
  if (isRecord(realm)) {
    roleValues(realm.roles).forEach((role) => result.add(role));
  }

  const resource = payload.resource_access;
  if (isRecord(resource)) {
    Object.values(resource).forEach((entry) => {
      if (isRecord(entry)) {
        roleValues(entry.roles).forEach((role) => result.add(role));
      }
    });
  }

  configuredRoles(payload, configuredClaims).forEach((role) => result.add(role));

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

function baseUrl(value: string): string {
  return value.replace(/\/+$/, "");
}

async function fetchJson(url: string, init: RequestInit): Promise<JsonRecord> {
  const response = await fetch(url, init);
  if (!response.ok) {
    throw unauthorized("Clerk OAuth token validation failed.");
  }

  const body: unknown = await response.json();
  if (!isRecord(body)) {
    throw unauthorized("Clerk OAuth token validation failed.");
  }

  return body;
}

export class Auth implements Authenticator {
  private readonly jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly env: Environment) {
    if (env.AUTH_MODE === "oidc" || env.AUTH_MODE === "dual") {
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

    if (this.env.AUTH_MODE === "clerk_oauth") {
      return this.verifyClerkOauth(token);
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
        roles: oidcRoles(payload, this.env.OIDC_ROLE_CLAIMS),
        scopes,
      };
    } catch (error) {
      if (error instanceof Error && error.name === "AppError") throw error;
      throw unauthorized("Access token validation failed.");
    }
  }

  private async verifyClerkOauth(token: string): Promise<Principal> {
    const frontendApiUrl = this.env.CLERK_FRONTEND_API_URL;
    const clientId = this.env.CLERK_OAUTH_CLIENT_ID;
    const clientSecret = this.env.CLERK_OAUTH_CLIENT_SECRET;

    if (!frontendApiUrl || !clientId || !clientSecret) {
      throw unauthorized("Clerk OAuth authentication is not configured.");
    }

    try {
      const credentials = Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
      const tokenInfo = await fetchJson(`${baseUrl(frontendApiUrl)}/oauth/token_info`, {
        method: "POST",
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({ token }),
      });

      if (tokenInfo.active !== true) {
        throw unauthorized("Clerk OAuth token is inactive.");
      }

      if (tokenInfo.client_id !== clientId) {
        throw unauthorized("Clerk OAuth token has an unexpected client_id.");
      }

      const scopes = [...new Set([...scopeValues(tokenInfo.scope), ...scopeValues(tokenInfo.scp)])].sort();
      if (!scopes.includes(this.env.CLERK_REQUIRED_SCOPE)) {
        throw unauthorized(`Clerk OAuth token is missing scope "${this.env.CLERK_REQUIRED_SCOPE}".`);
      }

      const userInfo = await fetchJson(`${baseUrl(frontendApiUrl)}/oauth/userinfo`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const subject = typeof userInfo.sub === "string" && userInfo.sub ? userInfo.sub : tokenInfo.sub;
      if (typeof subject !== "string" || !subject) {
        throw unauthorized("Clerk OAuth token is missing subject.");
      }

      return {
        subject,
        roles: configuredRoles({ ...tokenInfo, ...userInfo }, this.env.CLERK_ROLE_CLAIMS),
        scopes,
      };
    } catch (error) {
      if (error instanceof Error && error.name === "AppError") throw error;
      throw unauthorized("Clerk OAuth token validation failed.");
    }
  }
}
