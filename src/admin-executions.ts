import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { AppError, forbidden } from "./errors.js";
import { approvalRequiredFor, canApproveExecution, canRejectExecution } from "./approvals.js";
import { commandFromRow, type CommandRow, type JsonRecord, type TargetRow } from "./execution-runner.js";

type AdminPrincipal = Awaited<ReturnType<AdminService["principal"]>>;

const planInput = z.object({ target_id: z.string().uuid(), command_id: z.string().uuid() });
const confirmInput = z.object({ confirmation: z.literal("EJECUTAR") });
const rejectInput = z.object({ reason: z.string().min(5).max(500) });
const sshSecurityInput = z.object({
  known_hosts: z.string().min(20).max(10_000),
  secret_ref: z.string().min(5).max(500).nullable(),
});

function isRecord(value: unknown): value is JsonRecord { return !!value && typeof value === "object" && !Array.isArray(value); }
function first<T>(value: unknown, label: string): T {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0] as T;
}
function param(request: FastifyRequest): string {
  const id = (request.params as { id?: string }).id;
  if (!id) throw new AppError(400, "bad_request", "Missing id.");
  return id;
}
function permit(principal: AdminPrincipal, command: CommandRow): void {
  if (!command.allowed_roles.includes(principal.role)) throw forbidden("This command is not allowed for your role.");
}

async function audit(admin: AdminService, principal: AdminPrincipal, action: string, id: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", { method: "POST", body: { actor_id: principal.id, action, entity_type: "execution", entity_id: id, metadata }, prefer: "return=minimal" });
}

async function pair(admin: AdminService, targetId: string, commandId: string): Promise<{ target: TargetRow; command: CommandRow }> {
  const [targetValue, commandValue, mapping] = await Promise.all([
    admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled&limit=1` }),
    admin.rest("commands", { query: `id=eq.${encodeURIComponent(commandId)}&select=id,name,command_template,risk_level,requires_approval,allowed_roles,enabled,destructive,impact&limit=1` }),
    admin.rest("target_commands", { query: `target_id=eq.${encodeURIComponent(targetId)}&command_id=eq.${encodeURIComponent(commandId)}&select=target_id&limit=1` }),
  ]);
  const target = first<TargetRow>(targetValue, "Target");
  const command = first<CommandRow>(commandValue, "Command");
  if (!Array.isArray(mapping) || mapping.length === 0) throw forbidden("Command is not assigned to this target.");
  if (!target.enabled || !command.enabled) throw forbidden("Target or command is disabled.");
  return { target, command };
}

export function registerExecutionRoutes(server: FastifyInstance, admin: AdminService): void {
  server.patch("/admin/api/targets/:id/ssh-security", async (request) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Administrator role required.");
    const body = sshSecurityInput.parse(request.body);
    return { target: await admin.rest("targets", { method: "PATCH", query: `id=eq.${encodeURIComponent(param(request))}`, body }) };
  });

  server.post("/admin/api/executions/plan", async (request, reply) => {
    const principal = await admin.principal(request);
    const input = planInput.parse(request.body);
    const { target, command } = await pair(admin, input.target_id, input.command_id);
    permit(principal, command);
    const status = approvalRequiredFor(command) ? "approval_required" : "queued";
    const execution = first<JsonRecord>(await admin.rest("executions", { method: "POST", body: {
      target_id: target.id, command_id: command.id, requested_by: principal.id, status,
      command_rendered: commandFromRow(target, command),
    } }), "Execution");
    await audit(admin, principal, "execution.planned", String(execution.id), { target_id: target.id, command_id: command.id, risk_level: command.risk_level });
    return reply.code(201).send({ execution, confirmation_required: true });
  });

  server.post("/admin/api/executions/:id/confirm", async (request, reply) => {
    const principal = await admin.principal(request);
    confirmInput.parse(request.body);
    const id = param(request);
    const executionRow = first<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` }), "Execution");
    if (executionRow.status !== "queued" && executionRow.status !== "approval_required") throw new AppError(409, "invalid_status", "Execution cannot be confirmed.");
    if (executionRow.requested_by !== principal.id && principal.role !== "admin") throw forbidden("Only the requester or an administrator can confirm this execution.");
    const { target, command } = await pair(admin, String(executionRow.target_id), String(executionRow.command_id));
    permit(principal, command);
    const now = new Date().toISOString();
    await admin.rest("executions", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: { confirmed_at: now }, prefer: "return=minimal" });
    await audit(admin, principal, executionRow.status === "approval_required" ? "execution.confirmed_pending_approval" : "execution.confirmed", id);
    return reply.code(202).send({ id, status: executionRow.status });
  });

  server.get("/admin/api/approvals", async (request) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Approvals require an administrator.");
    return {
      approvals: await admin.rest("executions", {
        query: "status=eq.approval_required&select=*&order=created_at.asc&limit=100",
      }),
    };
  });

  server.post("/admin/api/executions/:id/approve", async (request, reply) => {
    const principal = await admin.principal(request);
    const id = param(request);
    const executionRow = first<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` }), "Execution");
    if (!canApproveExecution(principal, { status: String(executionRow.status), confirmed_at: typeof executionRow.confirmed_at === "string" ? executionRow.confirmed_at : null })) {
      throw forbidden("Only administrators can approve confirmed pending executions.");
    }
    const now = new Date().toISOString();
    await admin.rest("executions", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(id)}`,
      body: { status: "queued", approved_by: principal.id, approved_at: now, rejected_by: null, rejected_at: null, rejection_reason: null },
      prefer: "return=minimal",
    });
    await audit(admin, principal, "execution.approved", id);
    return reply.code(202).send({ id, status: "queued" });
  });

  server.post("/admin/api/executions/:id/reject", async (request, reply) => {
    const principal = await admin.principal(request);
    const id = param(request);
    const input = rejectInput.parse(request.body);
    const executionRow = first<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` }), "Execution");
    if (!canRejectExecution(principal, { status: String(executionRow.status) })) throw forbidden("Only administrators can reject pending executions.");
    const now = new Date().toISOString();
    await admin.rest("executions", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(id)}`,
      body: { status: "rejected", rejected_by: principal.id, rejected_at: now, rejection_reason: input.reason, finished_at: now },
      prefer: "return=minimal",
    });
    await audit(admin, principal, "execution.rejected", id, { reason: input.reason });
    return reply.code(202).send({ id, status: "rejected" });
  });

  server.get("/admin/api/executions/:id", async (request) => {
    await admin.principal(request);
    return { execution: first<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(param(request))}&select=*&limit=1` }), "Execution") };
  });

  server.get("/admin/api/executions/:id/events", async (request, reply) => {
    await admin.principal(request);
    const id = param(request);
    let lastId = Number((request.query as { after?: string }).after ?? 0);
    reply.hijack();
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    let closed = false;
    request.raw.on("close", () => { closed = true; });
    const send = async () => {
      if (closed) return;
      const rows = await admin.rest("execution_log_events", {
        query: `execution_id=eq.${encodeURIComponent(id)}&id=gt.${lastId}&select=id,stream,chunk,truncated,created_at&order=id.asc&limit=100`,
      });
      if (!Array.isArray(rows)) return;
      for (const row of rows) {
        if (!isRecord(row) || typeof row.id !== "number") continue;
        lastId = row.id;
        reply.raw.write(`id: ${row.id}\n`);
        reply.raw.write(`event: ${row.stream === "stderr" ? "stderr" : row.stream === "system" ? "system" : "stdout"}\n`);
        reply.raw.write(`data: ${JSON.stringify(row)}\n\n`);
      }
    };
    const interval = setInterval(() => { void send(); }, 1000);
    await send();
    request.raw.on("close", () => clearInterval(interval));
  });

  server.get("/admin/api/audit", async (request) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Audit logs require an administrator.");
    return { audit: await admin.rest("audit_logs", { query: "select=*&order=created_at.desc&limit=200" }) };
  });
}
