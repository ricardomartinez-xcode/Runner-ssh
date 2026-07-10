import { describe, expect, it } from "vitest";
import { approvalRequiredFor, canApproveExecution, canRejectExecution } from "../src/approvals.js";

describe("approvals", () => {
  it("requires approval for high risk or explicitly gated commands", () => {
    expect(approvalRequiredFor({ risk_level: "high", requires_approval: false })).toBe(true);
    expect(approvalRequiredFor({ risk_level: "medium", requires_approval: true })).toBe(true);
    expect(approvalRequiredFor({ risk_level: "low", requires_approval: false })).toBe(false);
  });

  it("allows only administrators to approve or reject pending executions", () => {
    expect(canApproveExecution({ role: "admin" }, { status: "approval_required", confirmed_at: "2026-07-10T12:00:00Z" })).toBe(true);
    expect(canApproveExecution({ role: "operator" }, { status: "approval_required", confirmed_at: "2026-07-10T12:00:00Z" })).toBe(false);
    expect(canRejectExecution({ role: "admin" }, { status: "approval_required" })).toBe(true);
    expect(canRejectExecution({ role: "viewer" }, { status: "approval_required" })).toBe(false);
  });
});
