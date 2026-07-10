import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AppError, forbidden } from "./errors.js";
import type { AdminPrincipal, AdminService } from "./admin.js";

const executionInput = z.object({
  target_id: z.string().uuid(),
  command_id: z.string().uuid(),
});

const confirmationInput = z.object({ confirmation: z.literal("EJECUTAR") });

type JsonRecord = Record<string, unknown>;
type TargetRow = {
  id: string;
  name: string;
  type: string;
  host: string;
  port: number;
  username: string;
  auth_type: "private_key" | "password" | "agent" | "token";
  secret_ref: string | null;
  working_directory: string | null;
  known_hosts: string | null;
  enabled: boolean;
};
type CommandRow = {
  id: string;
  name: string;
  command_template: string;
  risk_level: "low" | "medium" | "high";
  requires_approval: boolean;
  allowed_roles: string[];
  enabled: boolean;
};

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function firstRow<T>(value: unknown, label: string): T {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0] as T;
}

function executionId(request: FastifyRequest): string {
  const value = (request.params as { id?: string }).id;
  if (!value) throw new AppError(400, "bad_request", "Missing execution id.");
  return value;
}

function requireExecutionPermission(principal: AdminPrincipal, command: CommandRow): void {
  if (!command.allowed_roles.includes(principal.role)) throw forbidden("This command is not allowed for your role.");
  if (command.risk_level === "high" && principal.role !== "admin") throw forbidden("High-risk commands require an administrator.");
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function remoteCommand(target: TargetRow, command: CommandRow): string {
  if (!target.working_directory) return command.command_template;
  return `cd -- ${shellQuote(target.working_directory)} && ${command.command_template}`;
}

async function resolveSecret(reference: string | null): Promise<string | undefined> {
  if (!reference) return undefined;
  const normalized = reference.startsWith("RENDER_ENV:") ? reference.slice("RENDER_ENV:".length) : reference.startsWith("ENV:") ? reference.slice("ENV:".length) : null;
  if (normalized !== null) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(normalized)) throw new AppError(400, "invalid_secret_ref", "Invalid environment secret reference.");
    const value = process.env[normalized];
    if (!value) throw new AppError(500, "secret_resolution_failed", "Configured environment secret is missing.");
    return value;
  }
  if (reference.startsWith("1PASSWORD:")) {
    const opReference = reference.slice("1PASSWORD:".length);
    if (!opReference.startsWith("op://")) throw new AppError(400, "invalid_secret_ref", "Invalid 1Password reference.");
    if (!process.env.OP_SERVICE_ACCOUNT_TOKEN) throw new AppError(500, "secret_resolution_failed", "1Password service account is not configured.");
    return await new Promise<string>((resolve, reject) => {
      const child = spawn("op", ["read", opReference], { shell: false, stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
      child.on("error", () => reject(new AppError(500, "secret_provider_unavailable", "1Password CLI is unavailable.")));
      child.on("close", (code) => code === 0 && output.trim() ? resolve(output.trim()) : reject(new AppError(500, "secret_resolution_failed", "Target credential resolution failed.")));
    });
  }
  throw new AppError(400, "invalid_secret_ref", "Unsupported secret reference. Use ENV:, RENDER_ENV:, or 1PASSWORD:.");
}

async function runSsh(target: TargetRow, command: CommandRow, maxLogBytes: number): Promise<{ stdout: string; stderr: string; exitCode: number; durationMs: number }> {
  if (!["ssh", "tailscale", "cloudflare_tunnel"].includes(target.type)) throw new AppError(400, "unsupported_target", "This target type is not supported by the SSH executor.");
  if (!target.known_hosts?.trim()) throw new AppError(400, "known_hosts_required", "Strict SSH host verification requires a known_hosts entry.");
  if (target.auth_type === "token") throw new AppError(400, "unsupported_auth", "Token authentication is not supported for SSH targets.");

  const dir = await mkdtemp(join(tmpdir(), "relead-ops-"));
  const knownHostsPath = join(dir, "known_hosts");
  const keyPath = join(dir, "identity");
  const secret = target.auth_type === "agent" ? undefined : await resolveSecret(target.secret_ref);
  await writeFile(knownHostsPath, `${target.known_hosts.trim()}\n`, { mode: 0o600 });
  if (target.auth_type === "private_key") {
    if (!secret) throw new AppError(500, "secret_resolution_failed", "Private key is missing.");
    await writeFile(keyPath, `${secret.trim()}\n`, { mode: 0o600 });
  }

  const sshArgs = [
    "-p", String(target.port),
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${knownHostsPath}`,
    "-o", "ConnectTimeout=15",
  ];
  if (target.auth_type === "private_key") sshArgs.push("-i", keyPath, "-o", "IdentitiesOnly=yes");
  sshArgs.push(`${target.username}@${target.host}`, remoteCommand(target, command));

  const executable = target.auth_type === "password" ? "sshpass" : "ssh";
  const args = target.auth_type === "password" ? ["-e", "ssh", ...sshArgs] : sshArgs;
  const env = target.auth_type === "password" ? { ...process.env, SSHPASS: secret ?? "" } : process.env;
  const started = Date.now();

  try {
    return await new Promise((resolve, reject) => {
      const child = spawn(executable, args, { shell: false, env, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      const append = (current: string, chunk: Buffer) => (current + chunk.toString("utf8")).slice(-maxLogBytes);
      child.stdout.on("data", (chunk: Buffer) => { stdout = append(stdout, chunk); });
      child.stderr.on("data", (chunk: Buffer) => { stderr = append(stderr, chunk); });
      const timer = setTimeout(() => child.kill("SIGTERM"), 300_000);
      child.on("error", () => { clearTimeout(timer); reject(new AppError(500, "ssh_unavailable", "SSH client could not be started.")); });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, exitCode: code ?? 255, durationMs: Date.now() - started });
      });
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function audit(admin: AdminService, principal: AdminPrincipal, action: string, entityId: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", { method: "POST", body: { actor_id: principal.id, action, entity_type: "execution", entity_id: entityId, metadata }, prefer: "return=minimal" });
}

async function loadTargetAndCommand(admin: AdminService, targetId: string, commandId: string): Promise<{ target: TargetRow; command: CommandRow }> {
  const [targetValue, commandValue, mappingValue] = await Promise.all([
    admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled&limit=1` }),
    admin.rest("commands", { query: `id=eq.${encodeURIComponent(commandId)}&select=id,name,command_template,risk_level,requires_approval,allowed_roles,enabled&limit=1` }),
    admin.rest("target_commands", { query: `target_id=eq.${encodeURIComponent(targetId)}&command_id=eq.${encodeURIComponent(commandId)}&select=target_id&limit=1` }),
  ]);
  const target = firstRow<TargetRow>(targetValue, "Target");
  const command = firstRow<CommandRow>(commandValue, "Command");
  if (!Array.isArray(mappingValue) || mappingValue.length === 0) throw forbidden("Command is not assigned to this target.");
  if (!target.enabled || !command.enabled) throw forbidden("Target or command is disabled.");
  return { target, command };
}

export function registerExecutionRoutes(server: FastifyInstance, admin: AdminService): void {
  server.post("/admin/api/executions/plan", async (request, reply) => {
    const principal = await admin.principal(request);
    const input = executionInput.parse(request.body);
    const { target, command } = await loadTargetAndCommand(admin, input.target_id, input.command_id);
    requireExecutionPermission(principal, command);
    const needsApproval = command.requires_approval || command.risk_level === "high";
    const inserted = await admin.rest("executions", {
      method: "POST",
      body: {
        target_id: target.id,
        command_id: command.id,
        requested_by: principal.id,
        status: needsApproval ? "approval_required" : "queued",
        command_rendered: remoteCommand(target, command),
      },
    });
    const execution = firstRow<JsonRecord>(inserted, "Execution");
    await audit(admin, principal, "execution.planned", String(execution.id), { target_id: target.id, command_id: command.id, risk_level: command.risk_level });
    return reply.code(201).send({ execution, confirmation_required: true, next_step: 'Confirm with {"confirmation":"EJECUTAR"}.' });
  });

  server.post("/admin/api/executions/:id/confirm", async (request, reply) => {
    const principal = await admin.principal(request);
    confirmationInput.parse(request.body);
    const id = executionId(request);
    const value = await admin.rest("executions", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` });
    const execution = firstRow<JsonRecord>(value, "Execution");
    if (execution.status !== "queued" && execution.status !== "approval_required") throw new AppError(409, "invalid_status", "Execution cannot be confirmed in its current state.");
    const targetId = String(execution.target_id);
    const commandId = String(execution.command_id);
    const { target, command } = await loadTargetAndCommand(admin, targetId, commandId);
    requireExecutionPermission(principal, command);
    if (execution.status === "approval_required" && principal.role !== "admin") throw forbidden("Administrator approval is required.");

    await admin.rest("executions", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(id)}`,
      body: { status: "running", started_at: new Date().toISOString(), approved_by: principal.id, approved_at: new Date().toISOString() },
      prefer: "return=minimal",
    });
    await audit(admin, principal, "execution.confirmed", id, { target_id: targetId, command_id: commandId });

    void (async () => {
      try {
        const result = await runSsh(target, command, 65_536);
        const status = result.exitCode === 0 ? "succeeded" : "failed";
        await admin.rest("executions", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(id)}`,
          body: { status, stdout: result.stdout, stderr: result.stderr, exit_code: result.exitCode, duration_ms: result.durationMs, finished_at: new Date().toISOString() },
          prefer: "return=minimal",
        });
        await audit(admin, principal, `execution.${status}`, id, { exit_code: result.exitCode, duration_ms: result.durationMs });
      } catch (error) {
        const message = error instanceof Error ? error.message : "SSH execution failed.";
        await admin.rest("executions", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(id)}`,
          body: { status: "failed", error: message, finished_at: new Date().toISOString() },
          prefer: "return=minimal",
        });
        await audit(admin, principal, "execution.failed", id, { error: message });
      }
    })();

    return reply.code(202).send({ id, status: "running" });
  });

  server.get("/admin/api/executions/:id", async (request) => {
    await admin.principal(request);
    const id = executionId(request);
    return { execution: firstRow<JsonRecord>(await admin.rest("executions", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` }), "Execution") };
  });

  server.get("/admin/api/audit", async (request) => {
    const principal = await admin.principal(request);
    if (principal.role !== "admin") throw forbidden("Audit logs require an administrator.");
    return { audit: await admin.rest("audit_logs", { query: "select=*&order=created_at.desc&limit=200" }) };
  });
}
