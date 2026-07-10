import { describe, expect, it } from "vitest";
import { appendExecutionLog } from "../src/execution-log.js";

describe("appendExecutionLog", () => {
  it("redacts secrets before appending output", () => {
    const result = appendExecutionLog("", "Bearer github_pat_abcdefghijklmnopqrstuvwxyz012345", 2048);

    expect(result.value).toContain("[REDACTED]");
    expect(result.value).not.toContain("github_pat_");
    expect(result.truncated).toBe(false);
  });

  it("truncates logs at a configured byte limit", () => {
    const result = appendExecutionLog("abc", "defgh", 5);

    expect(result.value).toBe("abcde");
    expect(result.truncated).toBe(true);
  });
});
