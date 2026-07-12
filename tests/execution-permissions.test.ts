import { describe, expect, it } from "vitest";
import { executionPermissionDecision } from "../src/execution-permissions.js";

const target = { environment: "prod" as const };
const command = { allowed_roles: ["admin", "operator"] };

describe("granular execution permissions", () => {
  it("gives administrators full control", () => {
    expect(executionPermissionDecision({ id: "admin", role: "admin" }, target, command, {
      memberEnvironments: [], targetCanExecute: false, commandCanExecute: false,
    }).allowed).toBe(true);
  });

  it("keeps viewers read-only", () => {
    expect(executionPermissionDecision({ id: "viewer", role: "viewer" }, target, command, {
      memberEnvironments: ["prod"], targetCanExecute: true, commandCanExecute: true,
    })).toMatchObject({ allowed: false, reason: "viewer_read_only" });
  });

  it("requires target, command, and environment grants for operators", () => {
    const operator = { id: "operator", role: "operator" as const };
    expect(executionPermissionDecision(operator, target, command, {
      memberEnvironments: ["prod"], targetCanExecute: true, commandCanExecute: true,
    }).allowed).toBe(true);
    expect(executionPermissionDecision(operator, target, command, {
      memberEnvironments: ["dev"], targetCanExecute: true, commandCanExecute: true,
    }).reason).toBe("environment_not_allowed");
    expect(executionPermissionDecision(operator, target, command, {
      memberEnvironments: ["prod"], targetCanExecute: false, commandCanExecute: true,
    }).reason).toBe("target_not_allowed");
    expect(executionPermissionDecision(operator, target, command, {
      memberEnvironments: ["prod"], targetCanExecute: true, commandCanExecute: false,
    }).reason).toBe("command_not_allowed");
  });
});
