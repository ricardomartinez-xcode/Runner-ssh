export type AdminRole = "admin" | "operator" | "viewer";
export type RiskLevel = "low" | "medium" | "high";

export type ApprovalCommand = {
  risk_level: RiskLevel;
  requires_approval: boolean;
};

export type ApprovalPrincipal = {
  role: AdminRole;
};

export type ApprovalExecution = {
  status: string;
  confirmed_at?: string | null;
};

export function approvalRequiredFor(command: ApprovalCommand): boolean {
  return command.requires_approval || command.risk_level === "high";
}

export function canApproveExecution(principal: ApprovalPrincipal, execution: ApprovalExecution): boolean {
  return principal.role === "admin" && execution.status === "approval_required" && Boolean(execution.confirmed_at);
}

export function canRejectExecution(principal: ApprovalPrincipal, execution: Pick<ApprovalExecution, "status">): boolean {
  return principal.role === "admin" && execution.status === "approval_required";
}
