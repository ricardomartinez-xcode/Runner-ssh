import { afterEach, describe, expect, it } from "vitest";
import { cloudflareProxyCommand } from "../src/execution-runner.js";

const originalClientId = process.env.CF_ACCESS_CLIENT_ID;
const originalClientSecret = process.env.CF_ACCESS_CLIENT_SECRET;

afterEach(() => {
  if (originalClientId === undefined) delete process.env.CF_ACCESS_CLIENT_ID;
  else process.env.CF_ACCESS_CLIENT_ID = originalClientId;
  if (originalClientSecret === undefined) delete process.env.CF_ACCESS_CLIENT_SECRET;
  else process.env.CF_ACCESS_CLIENT_SECRET = originalClientSecret;
});

describe("cloudflareProxyCommand", () => {
  it("does not add a proxy for direct SSH targets", () => {
    expect(cloudflareProxyCommand({ type: "ssh" })).toBeUndefined();
  });

  it("requires non-interactive Cloudflare Access credentials", () => {
    delete process.env.CF_ACCESS_CLIENT_ID;
    delete process.env.CF_ACCESS_CLIENT_SECRET;
    expect(() => cloudflareProxyCommand({ type: "cloudflare_tunnel" })).toThrow(
      "Cloudflare Access service-token credentials are missing.",
    );
  });

  it("uses cloudflared as the OpenSSH ProxyCommand", () => {
    process.env.CF_ACCESS_CLIENT_ID = "client-id";
    process.env.CF_ACCESS_CLIENT_SECRET = "client-secret";
    expect(cloudflareProxyCommand({ type: "cloudflare_tunnel" })).toBe(
      "cloudflared access ssh --hostname %h",
    );
  });
});
