import { describe, expect, it } from "vitest";
import { redact } from "../src/redaction.js";

describe("redact", () => {
  it("redacts a GitHub token", () => {
    const result = redact("Bearer github_pat_abcdefghijklmnopqrstuvwxyz012345");
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("github_pat_");
  });

  it("redacts Supabase keys, JWTs, assignments, and configured secret values", () => {
    const previous = process.env.TEST_RELEAD_API_SECRET;
    process.env.TEST_RELEAD_API_SECRET = "configured-test-secret-value";
    try {
      const result = redact([
        "sb_secret_abcdefghijklmnopqrstuvwxyz012345",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.abcdefghijklmnopqrstuvwxyz012345",
        "DATABASE_PASSWORD=not-a-real-password",
        "configured-test-secret-value",
      ].join("\n"));
      expect(result).not.toContain("sb_secret_");
      expect(result).not.toContain("eyJhbGci");
      expect(result).not.toContain("not-a-real-password");
      expect(result).not.toContain("configured-test-secret-value");
    } finally {
      if (previous === undefined) delete process.env.TEST_RELEAD_API_SECRET;
      else process.env.TEST_RELEAD_API_SECRET = previous;
    }
  });
});
