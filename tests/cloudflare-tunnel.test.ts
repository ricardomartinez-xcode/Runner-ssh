import { afterEach, describe, expect, it } from "vitest";
import { cloudflareAccessEnvironment, cloudflareProxyCommand } from "../src/execution-runner.js";

const variableNames = [
  "TUNNEL_SERVICE_TOKEN_ID",
  "TUNNEL_SERVICE_TOKEN_SECRET",
  "CF_ACCESS_CLIENT_ID",
  "CF_ACCESS_CLIENT_SECRET",
] as const;
const originals = Object.fromEntries(variableNames.map((name) => [name, process.env[name]]));

afterEach(() => {
  for (const name of variableNames) {
    const original = originals[name];
    if (original === undefined) delete process.env[name];
    else process.env[name] = original;
  }
});

describe("cloudflareProxyCommand", () => {
  it("does not add a proxy for direct SSH targets", () => {
    expect(cloudflareProxyCommand({ type: "ssh" })).toBeUndefined();
  });

  it("requires non-interactive Cloudflare Access credentials", () => {
    for (const name of variableNames) delete process.env[name];
    expect(() => cloudflareProxyCommand({ type: "cloudflare_tunnel" })).toThrow(
      "Cloudflare Access service-token credentials are missing.",
    );
  });

  it("uses cloudflared with its native service-token environment", () => {
    process.env.TUNNEL_SERVICE_TOKEN_ID = "client-id";
    process.env.TUNNEL_SERVICE_TOKEN_SECRET = "client-secret";
    expect(cloudflareProxyCommand({ type: "cloudflare_tunnel" })).toBe(
      "cloudflared access ssh --hostname %h",
    );
    expect(cloudflareAccessEnvironment()).toEqual({
      TUNNEL_SERVICE_TOKEN_ID: "client-id",
      TUNNEL_SERVICE_TOKEN_SECRET: "client-secret",
    });
  });

  it("normalizes legacy service-token variable names", () => {
    delete process.env.TUNNEL_SERVICE_TOKEN_ID;
    delete process.env.TUNNEL_SERVICE_TOKEN_SECRET;
    process.env.CF_ACCESS_CLIENT_ID = "legacy-id";
    process.env.CF_ACCESS_CLIENT_SECRET = "legacy-secret";
    expect(cloudflareAccessEnvironment()).toEqual({
      TUNNEL_SERVICE_TOKEN_ID: "legacy-id",
      TUNNEL_SERVICE_TOKEN_SECRET: "legacy-secret",
    });
  });
});
