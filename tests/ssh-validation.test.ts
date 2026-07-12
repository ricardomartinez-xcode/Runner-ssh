import { describe, expect, it } from "vitest";
import { isValidDnsHostname, isValidSshHost, isValidSshUsername } from "../src/ssh-validation.js";

describe("SSH endpoint validation", () => {
  it("accepts ordinary DNS names and direct IP addresses", () => {
    expect(isValidDnsHostname("ssh.relead.com.mx")).toBe(true);
    expect(isValidSshHost("192.0.2.10")).toBe(true);
    expect(isValidSshHost("2001:db8::10")).toBe(true);
  });

  it("requires a DNS hostname for Cloudflare Tunnel", () => {
    expect(isValidSshHost("ssh.relead.com.mx", true)).toBe(true);
    expect(isValidSshHost("192.0.2.10", true)).toBe(false);
  });

  it("rejects shell metacharacters before ProxyCommand interpolation", () => {
    expect(isValidSshHost("ssh.relead.com.mx;env", true)).toBe(false);
    expect(isValidSshHost("$(id).example.com", true)).toBe(false);
    expect(isValidSshUsername("runner -oProxyCommand=id")).toBe(false);
  });

  it("accepts normal SSH usernames", () => {
    expect(isValidSshUsername("runner")).toBe(true);
    expect(isValidSshUsername("deploy-user")).toBe(true);
  });
});
