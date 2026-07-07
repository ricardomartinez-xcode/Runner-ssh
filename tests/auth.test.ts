import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { Auth } from "../src/auth.js";
import { loadEnvironment } from "../src/config.js";

const token = "test-runner-api-token-which-is-not-a-real-secret";
const tokenHash = createHash("sha256").update(token, "utf8").digest("hex");

function apiTokenEnvironment(mode: "api_token" | "dual" = "api_token") {
  return loadEnvironment({
    AUTH_MODE: mode,
    RUNNER_API_TOKEN_SHA256: tokenHash,
    RUNNER_API_TOKEN_ROLES: "runner.operator",
    ...(mode === "dual" ? {
      OIDC_ISSUER_URL: "https://issuer.example.test",
      OIDC_JWKS_URL: "https://issuer.example.test/.well-known/jwks.json",
      OIDC_AUDIENCE: "runner-api",
    } : {}),
  });
}

describe("Auth", () => {
  it("accepts a configured static Bearer token in api_token mode", async () => {
    const principal = await new Auth(apiTokenEnvironment()).verify(`Bearer ${token}`);

    expect(principal).toEqual({
      subject: "runner-api-token",
      roles: ["runner.operator"],
      scopes: ["runner:ssh"],
    });
  });

  it("accepts the static Bearer token before OIDC validation in dual mode", async () => {
    const principal = await new Auth(apiTokenEnvironment("dual")).verify(`Bearer ${token}`);
    expect(principal.roles).toEqual(["runner.operator"]);
  });

  it("rejects an unknown static Bearer token", async () => {
    await expect(new Auth(apiTokenEnvironment()).verify("Bearer wrong-token")).rejects.toMatchObject({
      statusCode: 401,
      code: "unauthorized",
    });
  });

  it("requires the static token settings in api_token mode", () => {
    expect(() => loadEnvironment({ AUTH_MODE: "api_token" })).toThrow();
  });
});
