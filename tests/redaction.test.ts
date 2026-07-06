import { describe, expect, it } from "vitest";
import { redact } from "../src/redaction.js";

describe("redact", () => {
  it("redacts a GitHub token", () => {
    const result = redact("Bearer github_pat_abcdefghijklmnopqrstuvwxyz012345");
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("github_pat_");
  });
});
