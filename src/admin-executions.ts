import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { AppError, forbidden } from "./errors.js";
import { readManagedCredential } from "./target-secrets.js";

type AdminPrincipal = Awaited<ReturnType<AdminService["principal"]>>;
type JsonRecord = Record<string, unknown>;
type TargetRow = {
  id: string; name: string; type: string; host: string; port: number; username: string;
  auth_type: "private_key" | "password" | "agent" | "token";
  secret_ref: string | null; working_directory: string | null; known_hosts: string | null; enabled: boolean;
};
type CommandRow = {
  id: string; name: string; command_template: string; risk_level: "low" | "medium" | "high";
  requires_approval: boolean; allowed_roles: string[]; enabled: boolean;
};

const planInput = z.object({ target_id: z.string().uuid(), command_id: z.string().uuid() });
const confirmInput = z.object({ confirmation: z.literal("EJECUTAR") });
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
  if (command.risk_level === "high" && principal.role !== "admin") throw forbidden("High-risk commands require an administrator.");
}
function quote(value: string): string { return `'${value.replace(/'/g, `'\\''`)}'`; }
function rendered(target: TargetRow, command: CommandRow): string {
  return target.working_directory ? `cd -- ${quote(target.working_directory)} && ${command.command_template}` : command.command_template;
}

async function secret(admin: AdminService, reference: string | null): Promise<string | undefined> {
  if (!reference) return undefined;
  if (reference.startsWith("MANAGED:")) return readManagedCredential(admin, reference);
  const envName = reference.startsWith("RENDER_ENV:") ? reference.slice(11) : reference.startsWith("ENV:") ? reference.slice(4) : undefined;
  if (envName !== undefined) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(envName)) throw new AppError(400, "invalid_secret_ref", "Invalid environment secret reference.");
    const value = process.env[envName];
    if (!value) throw new AppError(500, "secret_resolution_failed", "Configured environment secret is missing.");
    return value;
  }
  if (reference.startsWith("1PASSWORD:")) {
    const opRef = reference.slice(10);
    if (!opRef.startsWith("op://")) throw new AppError(400, "invalid_secret_ref", "Invalid 1Password reference.");
    if (!process.env.OP_SERVICE_ACCOUNT_TOKEN) throw new AppError(500, "secret_resolution_failed", "1Password is not configured.");
    return await new Promise((resolve, reject) => {
      const child = spawn("op", ["read", opRef], { shell: false, stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
      child.on("error", () => reject(new AppError(500, "secret_provider_unavailable", "1Password CLI is unavailable.")));
      child.on("close", (code) => code === 0 && output.trim() ? resolve(output.trim()) : reject(new AppError(500, "secret_resolution_failed", "Credential resolution failed.")));
    });
  }
  throw new AppError(400, "invalid_secret_ref", "Use a managed credential, a Render environment variable, or an advanced reference.");
}

async function execute(admin: AdminService, target: TargetRow, command: CommandRow): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }> {
  if (!["ssh", "tailscale", "cloudflare_tunnel"].includes(target.type)) throw new AppError(400, "unsupported_target", "Unsupported SSH target type.");
  if (!target.known_hosts?.trim()) throw new AppError(400, "known_hosts_required", "A known_hosts entry is required.");
  if (target.auth_type === "token") throw new AppError(400, "unsupported_auth", "Token authentication is not supported for SSH.");

  const dir = await mkdtemp(join(tmpdir(), "relead-ops-"));
  const knownHosts = join(dir, "known_hosts");
  const keyFile = join(dir, "identity");
  const credential = target.auth_type === "agent" ? undefined : await secret(admin, target.secret_ref);
  await writeFile(knownHosts, `${target.known_hosts.trim()}\n`, { mode: 0o600 });
  if (target.auth_type === "private_key") {
    if (!credential) throw new AppError(500, "secret_resolution_failed", "Private key is missing.");
    await writeFile(keyFile, `${credential.trim()}\n`, { mode: 0o600 });
  }

  const args = [
    "-p", String(target.port), "-o", `BatchMode=${target.auth_type === "password" ? "no" : "yes"}`,
    "-o", "StrictHostKeyChecking=yes", "-o", `UserKnownHostsFile=${knownHosts}`,
    "-o", "ConnectTimeout=15",
  ];
  if (target.auth_type === "private_key") args.push("-i", keyFile, "-o", "IdentitiesOnly=yes");
  args.push(`${target.username}@${target.host}`, rendered(target, command));

  const executable = target.auth_type === "password" ? "sshpass" : "ssh";
  const finalArgs = target.auth_type === "password" ? ["-e", "ssh", ...args] : args;
  const env = target.auth_type === "password" ? { ...process.env, SSHPASS: credential ?? "" } : process.env;
  const started = Date.now();
  try {
    return await new Promise((resolve, reject) => {
      const child = spawn(executable, finalArgs, { shell: false, env, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "";
      const append = (current: string, chunk: Buffer) => (current + chunk.toString("utf8")).slice(-65_536);
      child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
      child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });
      const timer = setTimeout(() => child.kill("SIGTERM"), 300_000);
      child.on("error", () => { clearTimeout(timer); reject(new AppError(500, "ssh_unavailable", "SSH client could not be started.")); });
      child.on("close", (code) => { clearTimeout(timer); resolve({ stdout, stderr, exitCode: code ?? 255, durationMs: Date.now() - started }); });
    });
  } finally { await rm(dir, { recursive: true, force: true }); }
}

async function audit(admin: AdminService, principal: AdminPrincipal, action: string, id: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", { method: "POST", body: { actor_id: principal.id, action, entity_type: "execution", entity_id: id, metadata }, prefer: "return=minimal" });
}

async function pair(admin: AdminService, targetId: string, commandId: string): Promise<{ target: TargetRow; command: CommandRow }> {
  const [targetValue, commandValue, mapping] = await Promise.all([
    admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled&limit=1` }),
    admin.rest("commands", { query: `id=eq.${encodeURIComponent(commandId)}&select=id,name,command_template,risk_level,requires_approval,allowed_roles,enabled&limit=1` }),
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
    const status = command.requires_approval || command.risk_level === "high" ? "approval_required" : "queued";
    const execution = first<JsonRecord>(await admin.rest("executions", { method: "POST", body: {
      target_id: target.id, command_id: command.id, requested_by: principal.id, status,
      command_rendered: rendered(target, command),
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
    const { target, command } = await pair(admin, String(executionRow.target_id), String(executionRow.command_id));
    permit(principal, command);
    if (executionRow.status === "approval_required" && principal.role !== "admin") throw forbidden("Administrator approval is required.");

    const now = new Date().toISOString();
    await admin.rest("executions", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: { status: "running", started_at: now, approved_by: principal.id, approved_at: now }, prefer: "return=minimal" });
    await audit(admin, principal, "execution.confirmed", id);

    void (async () => {
      try {
        const result = await execute(admin, target, command);
        const status = result.exitCode === 0 ? "succeeded" : "failed";
        await admin.rest("executions", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: {
          status, stdout: result.stdout, stderr: result.stderr, exit_code: result.exitCode,
          duration_ms: result.durationMs, finished_at: new Date().toISOString(),
        }, prefer: "return=minimal" });
        await audit(admin, principal, `execution.${status}`, id, { exit_code: result.exitCode, duration_ms: result.durationMs });
      } catch (error) {
        const message = error instanceof Error ? error.message : "SSH execution failed.";
        await admin.rest("executions", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: { status: "failed", error: message, finished_at: new Date().toISOString() }, prefer: "return=minimal" });
        await audit(admin, principal, "execution.failed", id, { error: message });
      }
    })();
    return reply.code(202).send({ id, status: "running" });
  });

  server.get("/admin/api/executions/:id", async (request) => {
    await admin.principal(request);
    return { execution: first<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(param(request))}&select=*&limit=1` }), "Execution") };
  });

  server.get("/admin/api/audit", async (request) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Audit logs require an administrator.");
    return { audit: await admin.rest("audit_logs", { query: "select=*&order=created_at.desc&limit=200" }) };
  });
}
