import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { AppError, forbidden } from "./errors.js";
import { isValidSshHost, isValidSshUsername } from "./ssh-validation.js";

type AdminRole = "admin" | "operator" | "viewer";
type JsonRecord = Record<string, unknown>;

type AdminPrincipal = {
  id: string;
  email: string;
  role: AdminRole;
  token: string;
};

const targetInput = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ssh", "cloudflare_tunnel"]),
  host: z.string().min(1).max(255).refine((value) => isValidSshHost(value), "Invalid SSH hostname or IP address."),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1).max(120).refine(isValidSshUsername, "Invalid SSH username."),
  auth_type: z.enum(["private_key", "password", "private_key_password", "agent"]).default("private_key"),
  secret_ref: z.string().max(500).nullable().optional(),
  tags: z.array(z.string().min(1).max(50)).max(20).default([]),
  working_directory: z.string().max(500).nullable().optional(),
  enabled: z.boolean().default(true),
});

const commandInput = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(500).nullable().optional(),
  command_template: z.string().min(1).max(2000),
  risk_level: z.enum(["low", "medium", "high"]).default("low"),
  requires_approval: z.boolean().default(false),
  allowed_roles: z.array(z.enum(["admin", "operator", "viewer"])).min(1).default(["admin", "operator"]),
  enabled: z.boolean().default(true),
  impact: z.string().max(500).nullable().optional(),
  destructive: z.boolean().default(false),
});

const userPermissionsInput = z.object({
  role: z.enum(["admin", "operator", "viewer"]),
  environments: z.array(z.enum(["prod", "staging", "dev"])).max(3),
  targets: z.array(z.object({
    target_id: z.string().uuid(),
    environment: z.enum(["prod", "staging", "dev"]),
  })).max(500),
  command_ids: z.array(z.string().uuid()).max(500),
});

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function bearer(request: FastifyRequest): string {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) throw new AppError(401, "unauthorized", "Supabase session required.");
  const token = header.slice(7).trim();
  if (!token) throw new AppError(401, "unauthorized", "Supabase session required.");
  return token;
}

function idParam(request: FastifyRequest): string {
  const value = (request.params as { id?: string }).id;
  if (!value) throw new AppError(400, "bad_request", "Missing id.");
  return value;
}

function requireRole(principal: AdminPrincipal, roles: AdminRole[]): void {
  if (!roles.includes(principal.role)) throw forbidden("Insufficient ReLead Ops permissions.");
}

const dangerousCommandPattern = /(?:^|\s)(?:rm|mv|dd|mkfs|shutdown|reboot|poweroff|halt|kill|pkill|systemctl\s+(?:restart|stop|disable)|docker(?:\s+(?:compose|system|volume|container|image))?\s+(?:prune|down|restart|rm|up|pull)|git\s+(?:pull|reset|clean|checkout)|apt(?:-get)?\s+(?:upgrade|dist-upgrade|autoremove|install|remove)|npm\s+(?:run|test|exec|ci|install)|npx)\b/i;

function enforceCommandSafety(input: z.infer<typeof commandInput>): z.infer<typeof commandInput> {
  const dangerous = input.destructive || dangerousCommandPattern.test(input.command_template);
  return {
    ...input,
    impact: input.impact ?? input.description ?? "May change target state or execute project-controlled code.",
    risk_level: "high",
    requires_approval: true,
    allowed_roles: ["admin"],
    destructive: dangerous,
  };
}

async function auditMutation(admin: AdminService, principal: AdminPrincipal, action: string, entityType: string, entityId: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", {
    method: "POST",
    body: { actor_id: principal.id, action, entity_type: entityType, entity_id: entityId, metadata },
    prefer: "return=minimal",
  });
}

export class AdminService {
  readonly enabled: boolean;
  private readonly url: string;
  private readonly publishableKey: string;
  private readonly secretKey: string;

  constructor(source: NodeJS.ProcessEnv = process.env) {
    this.url = (source.SUPABASE_URL ?? "").replace(/\/+$/, "");
    this.publishableKey = source.SUPABASE_PUBLISHABLE_KEY ?? source.SUPABASE_ANON_KEY ?? "";
    this.secretKey = source.SUPABASE_SECRET_KEY ?? source.SUPABASE_SERVICE_ROLE_KEY ?? "";
    this.enabled = Boolean(this.url && this.publishableKey && this.secretKey);
  }

  publicConfig() {
    return { enabled: this.enabled, supabaseUrl: this.url, publishableKey: this.publishableKey };
  }

  async principal(request: FastifyRequest): Promise<AdminPrincipal> {
    if (!this.enabled) throw new AppError(503, "admin_unavailable", "Supabase admin integration is not configured.");
    const token = bearer(request);
    const userResponse = await fetch(`${this.url}/auth/v1/user`, {
      headers: { apikey: this.publishableKey, Authorization: `Bearer ${token}` },
    });
    if (!userResponse.ok) throw new AppError(401, "unauthorized", "Invalid or expired Supabase session.");
    const user: unknown = await userResponse.json();
    if (!isRecord(user) || typeof user.id !== "string") throw new AppError(401, "unauthorized", "Invalid Supabase user.");

    const profiles = await this.rest("profiles", {
      query: `id=eq.${encodeURIComponent(user.id)}&select=id,email,role&limit=1`,
    });
    const profile = Array.isArray(profiles) && isRecord(profiles[0]) ? profiles[0] : undefined;
    if (!profile) throw new AppError(403, "profile_missing", "ReLead Ops profile not found.");
    const role = profile.role;
    if (role !== "admin" && role !== "operator" && role !== "viewer") throw forbidden("Invalid ReLead Ops role.");

    return {
      id: user.id,
      email: typeof profile.email === "string" ? profile.email : typeof user.email === "string" ? user.email : "",
      role,
      token,
    };
  }

  async rest(table: string, options: { method?: string; query?: string; body?: unknown; prefer?: string } = {}): Promise<unknown> {
    const response = await fetch(`${this.url}/rest/v1/${table}${options.query ? `?${options.query}` : ""}`, {
      method: options.method ?? "GET",
      headers: {
        apikey: this.secretKey,
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
        Prefer: options.prefer ?? "return=representation",
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new AppError(response.status, "supabase_error", message || "Supabase request failed.");
    }
    if (response.status === 204) return null;
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }

  async rpc(functionName: string, body: Record<string, unknown> = {}): Promise<unknown> {
    const response = await fetch(`${this.url}/rest/v1/rpc/${functionName}`, {
      method: "POST",
      headers: {
        apikey: this.secretKey,
        Authorization: `Bearer ${this.secretKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new AppError(response.status, "supabase_error", message || "Supabase RPC request failed.");
    }
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }
}

export function registerAdminRoutes(server: FastifyInstance, admin: AdminService): void {
  server.get("/admin", async (_request, reply) => reply.redirect("/admin/manage"));
  server.get("/admin/config", async () => admin.publicConfig());

  server.get("/admin/api/me", async (request) => {
    const principal = await admin.principal(request);
    return { user: { id: principal.id, email: principal.email, role: principal.role } };
  });

  server.get("/admin/api/dashboard", async (request) => {
    await admin.principal(request);
    const [targets, executions, health] = await Promise.all([
      admin.rest("targets", { query: "select=id,name,type,enabled,created_at&order=created_at.desc" }),
      admin.rest("executions", { query: "select=id,status,created_at,target_id,command_id&order=created_at.desc&limit=10" }),
      admin.rest("health_checks", { query: "select=target_id,status,latency_ms,checked_at&order=checked_at.desc&limit=100" }),
    ]);
    const targetRows = Array.isArray(targets) ? targets : [];
    const healthRows = Array.isArray(health) ? health : [];
    const latestByTarget = new Map<string, JsonRecord>();
    for (const row of healthRows) {
      if (isRecord(row) && typeof row.target_id === "string" && !latestByTarget.has(row.target_id)) latestByTarget.set(row.target_id, row);
    }
    return {
      summary: {
        targets: targetRows.length,
        enabled: targetRows.filter((row) => isRecord(row) && row.enabled === true).length,
        online: [...latestByTarget.values()].filter((row) => row.status === "online").length,
        offline: [...latestByTarget.values()].filter((row) => row.status === "offline").length,
        degraded: [...latestByTarget.values()].filter((row) => row.status === "degraded").length,
        unknown: [...latestByTarget.values()].filter((row) => row.status === "unknown").length,
        unchecked: Math.max(0, targetRows.length - latestByTarget.size),
      },
      targets,
      executions,
      health: [...latestByTarget.values()],
    };
  });

  server.get("/admin/api/targets", async (request) => {
    await admin.principal(request);
    return { targets: await admin.rest("targets", { query: "select=*&order=created_at.desc" }) };
  });
  server.post("/admin/api/targets", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = targetInput.parse(request.body);
    const target = await admin.rest("targets", { method: "POST", body: { ...body, enabled: false, disabled_reason: "Legacy endpoint requires worker verification before activation.", created_by: principal.id } });
    const row = Array.isArray(target) && isRecord(target[0]) ? target[0] : undefined;
    if (row && typeof row.id === "string") await auditMutation(admin, principal, "target.created_legacy_disabled", "target", row.id);
    return reply.code(201).send({ target });
  });
  server.patch("/admin/api/targets/:id", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = targetInput.partial().parse(request.body);
    const id = idParam(request);
    const target = await admin.rest("targets", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: { ...body, enabled: false, disabled_reason: "Legacy update requires worker verification before activation." } });
    await auditMutation(admin, principal, "target.updated_legacy_disabled", "target", id);
    return { target };
  });
  server.delete("/admin/api/targets/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const id = idParam(request);
    await auditMutation(admin, principal, "target.deletion_requested_legacy", "target", id);
    await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(id)}`, prefer: "return=minimal" });
    await auditMutation(admin, principal, "target.deleted_legacy", "target", id);
    return reply.code(204).send();
  });

  server.get("/admin/api/commands", async (request) => {
    await admin.principal(request);
    return { commands: await admin.rest("commands", { query: "select=*&order=created_at.desc" }) };
  });
  server.post("/admin/api/commands", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const body = enforceCommandSafety(commandInput.parse(request.body));
    const command = await admin.rest("commands", { method: "POST", body: { ...body, created_by: principal.id } });
    const row = Array.isArray(command) && isRecord(command[0]) ? command[0] : undefined;
    if (row && typeof row.id === "string") await auditMutation(admin, principal, "command.created", "command", row.id, { risk_level: body.risk_level, destructive: body.destructive });
    return reply.code(201).send({ command });
  });
  server.patch("/admin/api/commands/:id", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const id = idParam(request);
    const currentValue = await admin.rest("commands", { query: `id=eq.${encodeURIComponent(id)}&select=*&limit=1` });
    const current = Array.isArray(currentValue) && isRecord(currentValue[0]) ? currentValue[0] : undefined;
    if (!current) throw new AppError(404, "not_found", "Command not found.");
    const merged = enforceCommandSafety(commandInput.parse({ ...current, ...commandInput.partial().parse(request.body) }));
    const command = await admin.rest("commands", { method: "PATCH", query: `id=eq.${encodeURIComponent(id)}`, body: merged });
    await auditMutation(admin, principal, "command.updated", "command", id, { risk_level: merged.risk_level, destructive: merged.destructive });
    return { command };
  });
  server.delete("/admin/api/commands/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const id = idParam(request);
    await auditMutation(admin, principal, "command.deletion_requested", "command", id);
    await admin.rest("commands", { method: "DELETE", query: `id=eq.${encodeURIComponent(id)}`, prefer: "return=minimal" });
    await auditMutation(admin, principal, "command.deleted", "command", id);
    return reply.code(204).send();
  });

  server.get("/admin/api/executions", async (request) => {
    await admin.principal(request);
    return { executions: await admin.rest("executions", { query: "select=*&order=created_at.desc&limit=100" }) };
  });
  server.get("/admin/api/health", async (request) => {
    await admin.principal(request);
    return { health: await admin.rest("health_checks", { query: "select=*&order=checked_at.desc&limit=200" }) };
  });

  server.get("/admin/api/users", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    return {
      users: await admin.rest("profiles", { query: "select=id,email,full_name,role,created_at,updated_at&order=email.asc" }),
      organization_members: await admin.rest("organization_members", { query: "select=*&limit=500" }),
      target_permissions: await admin.rest("target_permissions", { query: "select=*&limit=500" }),
      command_permissions: await admin.rest("command_permissions", { query: "select=*&limit=500" }),
      targets: await admin.rest("targets", { query: "select=id,name,environment,enabled&order=name.asc&limit=500" }),
      commands: await admin.rest("commands", { query: "select=id,name,risk_level,enabled&order=name.asc&limit=500" }),
    };
  });

  server.put("/admin/api/users/:id/permissions", async (request) => {
    const principal = await admin.principal(request);
    requireRole(principal, ["admin"]);
    const userId = idParam(request);
    const input = userPermissionsInput.parse(request.body);
    const profiles = await admin.rest("profiles", { query: `id=eq.${encodeURIComponent(userId)}&select=id,email,role&limit=1` });
    const profile = Array.isArray(profiles) && isRecord(profiles[0]) ? profiles[0] : undefined;
    if (!profile) throw new AppError(404, "not_found", "User profile not found.");

    if (profile.role === "admin" && input.role !== "admin") {
      const admins = await admin.rest("profiles", { query: "role=eq.admin&select=id&limit=2" });
      if (!Array.isArray(admins) || admins.length <= 1) throw new AppError(409, "last_admin", "The last administrator cannot be demoted.");
    }

    const environments = input.role === "admin" ? ["prod", "staging", "dev"] : [...new Set(input.environments)];
    await admin.rest("profiles", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(userId)}`,
      body: { role: input.role, updated_at: new Date().toISOString() },
      prefer: "return=minimal",
    });
    await admin.rest("organization_members", {
      method: "POST",
      query: "on_conflict=user_id",
      body: { user_id: userId, role: input.role, environments, updated_at: new Date().toISOString() },
      prefer: "resolution=merge-duplicates,return=minimal",
    });

    await admin.rest("target_permissions", { method: "DELETE", query: `user_id=eq.${encodeURIComponent(userId)}`, prefer: "return=minimal" });
    if (input.role === "operator" && input.targets.length) {
      await admin.rest("target_permissions", {
        method: "POST",
        body: input.targets.map((target) => ({ user_id: userId, target_id: target.target_id, environment: target.environment, can_execute: true, can_manage: false })),
        prefer: "return=minimal",
      });
    }

    await admin.rest("command_permissions", { method: "DELETE", query: `user_id=eq.${encodeURIComponent(userId)}`, prefer: "return=minimal" });
    if (input.role === "operator" && input.command_ids.length) {
      await admin.rest("command_permissions", {
        method: "POST",
        body: input.command_ids.map((commandId) => ({ user_id: userId, command_id: commandId, can_execute: true })),
        prefer: "return=minimal",
      });
    }

    await admin.rest("audit_logs", {
      method: "POST",
      body: {
        actor_id: principal.id,
        action: "user.permissions_updated",
        entity_type: "profile",
        entity_id: userId,
        metadata: {
          role: input.role,
          environments,
          target_ids: input.targets.map((target) => target.target_id),
          command_ids: input.command_ids,
        },
      },
      prefer: "return=minimal",
    });
    return { ok: true };
  });
}
