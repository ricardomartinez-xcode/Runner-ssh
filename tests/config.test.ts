import { describe, expect, it } from "vitest";
import { loadEnvironment } from "../src/config.js";

const apiAuth = {
  AUTH_MODE: "api_token",
  RUNNER_API_TOKEN_SHA256: "a".repeat(64),
  RUNNER_API_TOKEN_ROLES: "runner.operator",
};

describe("production environment configuration", () => {
  it("parses an explicit false break-glass flag as disabled", () => {
    expect(loadEnvironment({ ...apiAuth, BREAK_GLASS_ENABLED: "false" }).BREAK_GLASS_ENABLED).toBe(false);
  });

  it("fails closed when break-glass is enabled without all recovery controls", () => {
    expect(() => loadEnvironment({ ...apiAuth, BREAK_GLASS_ENABLED: "true" })).toThrow();
  });

  it("rejects ambiguous break-glass boolean values", () => {
    expect(() => loadEnvironment({ ...apiAuth, BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS: "tru" })).toThrow();
  });

  it("rejects a non-Cloudflare Access issuer", () => {
    expect(() => loadEnvironment({
      ...apiAuth,
      BREAK_GLASS_ENABLED: "true",
      BREAK_GLASS_KEY_SHA256: "b".repeat(64),
      BREAK_GLASS_SESSION_SECRET: "session-secret-that-is-long-enough-for-tests",
      BREAK_GLASS_RENDER_PRIVATE_KEY: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
      BREAK_GLASS_RENDER_SERVICE_ID: "srv-abc123",
      BREAK_GLASS_RENDER_SSH_HOST: "ssh.oregon.render.com",
      BREAK_GLASS_RENDER_KNOWN_HOSTS: "ssh.oregon.render.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
      CLOUDFLARE_ACCESS_TEAM_DOMAIN: "https://example.invalid",
      CLOUDFLARE_ACCESS_AUD: "test-access-audience",
    })).toThrow();
  });
});
