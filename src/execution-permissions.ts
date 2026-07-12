export type ExecutionPermissionPrincipal = {
  id: string;
  role: "admin" | "operator" | "viewer";
};

export type ExecutionPermissionTarget = {
  environment?: "prod" | "staging" | "dev";
};

export type ExecutionPermissionCommand = {
  allowed_roles: string[];
};

export type ExecutionPermissionGrants = {
  memberEnvironments: string[];
  targetCanExecute: boolean;
  commandCanExecute: boolean;
};

export type ExecutionPermissionDecision = {
  allowed: boolean;
  reason: string;
};

export function executionPermissionDecision(
  principal: ExecutionPermissionPrincipal,
  target: ExecutionPermissionTarget,
  command: ExecutionPermissionCommand,
  grants: ExecutionPermissionGrants,
): ExecutionPermissionDecision {
  if (principal.role === "admin") return { allowed: true, reason: "administrator" };
  if (principal.role !== "operator") return { allowed: false, reason: "viewer_read_only" };
  if (!command.allowed_roles.includes("operator")) return { allowed: false, reason: "role_not_allowed" };

  const environment = target.environment ?? "dev";
  if (!grants.memberEnvironments.includes(environment)) return { allowed: false, reason: "environment_not_allowed" };
  if (!grants.targetCanExecute) return { allowed: false, reason: "target_not_allowed" };
  if (!grants.commandCanExecute) return { allowed: false, reason: "command_not_allowed" };
  return { allowed: true, reason: "explicit_grants" };
}
