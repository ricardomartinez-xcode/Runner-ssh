import { describe, expect, it } from "vitest";
import {
  availableTargetTypes,
  normalizeCredentialReference,
  validateTargetCredential,
} from "../src/target-onboarding.js";

describe("target onboarding", () => {
  it("exposes only target types that the Render worker can execute today", () => {
    expect(availableTargetTypes().map((entry) => entry.value)).toEqual(["ssh", "cloudflare_tunnel"]);
  });

  it("validates password confirmation before a managed password can be stored", () => {
    expect(() => validateTargetCredential({
      authType: "password",
      source: "managed",
      credential: "one",
      credentialConfirmation: "two",
    })).toThrow(/match/i);
  });

  it("rejects pasted private keys that are not OpenSSH or PEM keys", () => {
    expect(() => validateTargetCredential({
      authType: "private_key",
      source: "managed",
      credential: "not a key",
    })).toThrow(/private key/i);
  });

  it("normalizes Render environment variables without accepting raw secret values", () => {
    expect(normalizeCredentialReference({
      source: "environment",
      environmentVariable: "RELEADSERVER_SSH_KEY",
    })).toBe("RENDER_ENV:RELEADSERVER_SSH_KEY");

    expect(() => normalizeCredentialReference({
      source: "environment",
      environmentVariable: "ssh-password=secret",
    })).toThrow(/variable/i);
  });
});
