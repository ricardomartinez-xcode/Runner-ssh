import { spawn } from "node:child_process";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { AppError, forbidden } from "./errors.js";
import { isValidSshHost, isValidSshUsername } from "./ssh-validation.js";
import { availableTargetTypes, normalizeCredentialReference, validateTargetCredential } from "./target-onboarding.js";
import { deleteManagedCredential, managedCredentialsEnabled, storeManagedCredential } from "./target-secrets.js";

type JsonRecord = Record<string, unknown>;

const targetInput = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ssh", "cloudflare_tunnel"]),
  host: z.string().min(1).max(255).refine((value) => isValidSshHost(value), "Invalid SSH hostname or IP address."),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1).max(120).refine(isValidSshUsername, "Invalid SSH username."),
  auth_type: z.enum(["private_key", "password", "private_key_password", "agent"]).default("private_key"),
  credential_source: z.enum(["managed", "environment", "agent", "reference"]).default("managed"),
  credential: z.string().max(50_000).optional(),
  credential_confirmation: z.string().max(50_000).optional(),
  private_key: z.string().max(50_000).optional(),
  password: z.string().max(10_000).optional(),
  password_confirmation: z.string().max(10_000).optional(),
  environment_variable: z.string().max(120).optional(),
  secret_reference: z.string().max(500).optional(),
  tags: z.array(z.string().min(1).max(50)).max(20).default([]),
  environment: z.enum(["prod", "staging", "dev"]).default("dev"),
  working_directory: z.string().max(500).nullable().optional(),
  known_hosts: z.string().max(10_000).nullable().optional(),
  enabled: z.boolean().default(true),
  command_ids: z.array(z.string().uuid()).max(100).optional(),
}).superRefine((value, ctx) => {
  if (!isValidSshHost(value.host, value.type === "cloudflare_tunnel")) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["host"], message: value.type === "cloudflare_tunnel" ? "Cloudflare Tunnel targets require a DNS hostname." : "Invalid SSH hostname or IP address." });
  }
  if (value.enabled && !value.known_hosts?.trim()) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["known_hosts"], message: "An enabled target requires a confirmed known_hosts entry." });
  }
  if ((value.auth_type === "agent") !== (value.credential_source === "agent")) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["credential_source"], message: "SSH Agent must be selected as both the authentication method and credential source." });
  }
});

const scanInput = z.object({
  host: z.string().min(1).max(255).regex(/^[A-Za-z0-9._:[\]-]+$/, "Invalid host."),
  port: z.coerce.number().int().min(1).max(65535).default(22),
});
const connectionTestInput = z.object({ enable_on_success: z.boolean().default(false) });

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function first<T extends JsonRecord = JsonRecord>(value: unknown, label: string): T {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0] as T;
}

function idParam(request: FastifyRequest): string {
  const value = (request.params as { id?: string }).id;
  if (!value) throw new AppError(400, "bad_request", "Missing target id.");
  return value;
}

function requireAdmin(role: string): void {
  if (role !== "admin") throw forbidden("Only administrators can manage targets and credentials.");
}

async function audit(admin: AdminService, actorId: string, action: string, targetId: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", {
    method: "POST",
    body: { actor_id: actorId, action, entity_type: "target", entity_id: targetId, metadata },
    prefer: "return=minimal",
  });
}
function targetRecord(input: z.infer<typeof targetInput>, secretRef: string | null): JsonRecord {
  return {
    name: input.name,
    type: input.type,
    host: input.host,
    port: input.port,
    username: input.username,
    auth_type: input.credential_source === "agent" ? "agent" : input.auth_type,
    secret_ref: input.credential_source === "agent" ? null : secretRef,
    tags: input.tags,
    environment: input.environment,
    working_directory: input.working_directory ?? null,
    known_hosts: input.known_hosts ?? null,
    enabled: input.enabled,
  };
}

function managedCredentialValue(input: z.infer<typeof targetInput>): string {
  if (input.auth_type === "private_key_password") {
    return JSON.stringify({ private_key: input.private_key ?? "", password: input.password ?? "" });
  }
  if (input.auth_type === "private_key" && input.private_key !== undefined) return input.private_key;
  if (input.auth_type === "password" && input.password !== undefined) return input.password;
  return input.credential ?? "";
}

function hasManagedCredentialInput(input: z.infer<typeof targetInput>): boolean {
  if (input.auth_type === "private_key_password") return Boolean(input.private_key?.trim() || input.password?.trim());
  if (input.auth_type === "private_key") return Boolean((input.private_key ?? input.credential)?.trim());
  if (input.auth_type === "password") return Boolean((input.password ?? input.credential)?.trim());
  return false;
}

function validateInputCredential(input: z.infer<typeof targetInput>): void {
  if (input.auth_type === "agent" && !process.env.SSH_AUTH_SOCK) {
    throw new AppError(503, "ssh_agent_unavailable", "SSH Agent is not available in this worker runtime.");
  }
  validateTargetCredential({
    authType: input.auth_type,
    source: input.credential_source,
    credential: managedCredentialValue(input),
    credentialConfirmation: input.credential_confirmation,
    privateKey: input.private_key,
    password: input.password,
    passwordConfirmation: input.password_confirmation,
  });
}

async function queueConnectionTest(admin: AdminService, actorId: string, targetId: string, enableOnSuccess: boolean): Promise<JsonRecord> {
  const active = await admin.rest("target_connection_tests", {
    query: `target_id=eq.${encodeURIComponent(targetId)}&status=in.(queued,running)&select=*&order=created_at.desc&limit=1`,
  });
  if (Array.isArray(active) && isRecord(active[0])) {
    if (enableOnSuccess && active[0].enable_on_success !== true) {
      await admin.rest("target_connection_tests", {
        method: "PATCH",
        query: `id=eq.${encodeURIComponent(String(active[0].id))}&status=in.(queued,running)`,
        body: { enable_on_success: true },
        prefer: "return=minimal",
      });
      active[0].enable_on_success = true;
    }
    return active[0];
  }

  const test = first(await admin.rest("target_connection_tests", {
    method: "POST",
    body: { target_id: targetId, requested_by: actorId, status: "queued", enable_on_success: enableOnSuccess },
  }), "Connection test");
  await admin.rest("targets", {
    method: "PATCH",
    query: `id=eq.${encodeURIComponent(targetId)}`,
    body: { last_test_status: "unknown", last_test_message: "Connection test queued for the worker." },
    prefer: "return=minimal",
  });
  await audit(admin, actorId, "target.connection_test_requested", targetId, { connection_test_id: test.id, enable_on_success: enableOnSuccess });
  return test;
}

async function scanHostKey(host: string, port: number): Promise<string> {
  if (host.startsWith("-")) throw new AppError(400, "invalid_host", "Invalid host.");
  return await new Promise((resolve, reject) => {
    const child = spawn("ssh-keyscan", ["-T", "7", "-p", String(port), host], { shell: false, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout = (stdout + chunk.toString("utf8")).slice(-20_000); });
    child.stderr.on("data", (chunk: Buffer) => { stderr = (stderr + chunk.toString("utf8")).slice(-4_000); });
    child.on("error", () => reject(new AppError(500, "ssh_keyscan_unavailable", "ssh-keyscan is unavailable in the runner image.")));
    child.on("close", (code) => {
      const keys = stdout.split("\n").filter((line) => line.trim() && !line.startsWith("#")).join("\n").trim();
      if (code !== 0 || !keys) reject(new AppError(502, "host_key_scan_failed", stderr.trim() || "No SSH host key was returned."));
      else resolve(keys);
    });
  });
}

export function registerImprovedTargetRoutes(server: FastifyInstance, admin: AdminService): void {
  server.get("/admin/manage-v2", async (_request, reply) => reply.redirect("/admin/manage"));

  server.get("/admin/api/v2/config", async (request) => {
    await admin.principal(request);
    return { managed_credentials_enabled: managedCredentialsEnabled(), ssh_agent_available: Boolean(process.env.SSH_AUTH_SOCK), target_types: availableTargetTypes() };
  });

  server.get("/admin/api/v2/targets", async (request) => {
    await admin.principal(request);
    return { targets: await admin.rest("targets", { query: "select=*&order=created_at.desc" }) };
  });

  server.post("/admin/api/v2/scan-host-key", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const input = scanInput.parse(request.body);
    return {
      known_hosts: await scanHostKey(input.host, input.port),
      warning: "Compare the fingerprint with a trusted source before saving the target.",
    };
  });

  server.post("/admin/api/v2/targets", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const input = targetInput.parse(request.body);

    let initialRef = normalizeCredentialReference({
      source: input.credential_source,
      environmentVariable: input.environment_variable,
      secretReference: input.secret_reference,
    });
    validateInputCredential(input);
    const enableAfterTest = input.enabled;

    const created = await admin.rest("targets", {
      method: "POST",
      body: {
        ...targetRecord(input, initialRef),
        enabled: false,
        disabled_reason: enableAfterTest ? "Pending worker SSH connection test." : "Created disabled by administrator.",
        created_by: principal.id,
      },
    });
    const row = first(created, "Target");
    const targetId = String(row.id);

    try {
      if (input.credential_source === "managed") {
        const managedRef = await storeManagedCredential(admin, targetId, managedCredentialValue(input), principal.id);
        await admin.rest("targets", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(targetId)}`,
          body: { secret_ref: managedRef },
          prefer: "return=minimal",
        });
        row.secret_ref = managedRef;
      }
      if (input.command_ids?.length) {
        await admin.rest("target_commands", {
          method: "POST",
          body: input.command_ids.map((commandId) => ({ target_id: targetId, command_id: commandId })),
          prefer: "return=minimal",
        });
      }
      await audit(admin, principal.id, "target.created", targetId, {
        name: input.name,
        type: input.type,
        credential_source: input.credential_source,
      });
      const connectionTest = enableAfterTest ? await queueConnectionTest(admin, principal.id, targetId, true) : null;
      return reply.code(201).send({ target: { ...row, enabled: false }, connection_test: connectionTest });
    } catch (error) {
      await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(targetId)}`, prefer: "return=minimal" });
      throw error;
    }
  });

  server.patch("/admin/api/v2/targets/:id", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    const input = targetInput.parse(request.body);
    const current = first(await admin.rest("targets", {
      query: `id=eq.${encodeURIComponent(targetId)}&select=*&limit=1`,
    }), "Target");
    const previousRef = typeof current.secret_ref === "string" ? current.secret_ref : null;

    let nextRef: string | null = previousRef;
    let managedReplacement: string | undefined;
    if (input.credential_source === "managed") {
      if (hasManagedCredentialInput(input)) {
        validateInputCredential(input);
        managedReplacement = managedCredentialValue(input);
      } else if (!previousRef?.startsWith("MANAGED:")) {
        throw new AppError(400, "credential_required", "Enter a credential when switching this target to managed storage.");
      }
    } else if (input.credential_source === "environment") {
      nextRef = normalizeCredentialReference({ source: input.credential_source, environmentVariable: input.environment_variable });
    } else if (input.credential_source === "reference") {
      nextRef = normalizeCredentialReference({ source: input.credential_source, secretReference: input.secret_reference });
    } else {
      nextRef = null;
    }

    const connectionFieldsChanged = ["type", "host", "port", "username", "auth_type", "known_hosts"].some((key) => String(current[key] ?? "") !== String(targetRecord(input, nextRef)[key] ?? ""));
    const credentialChanged = managedReplacement !== undefined || nextRef !== previousRef;
    const needsEnableTest = input.enabled && (current.last_test_status !== "passed" || connectionFieldsChanged || credentialChanged);
    const effectiveEnabled = input.enabled && !needsEnableTest;
    if (managedReplacement !== undefined) {
      nextRef = await storeManagedCredential(admin, targetId, managedReplacement, principal.id);
    }

    await admin.rest("targets", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(targetId)}`,
      body: {
        ...targetRecord(input, nextRef),
        enabled: effectiveEnabled,
        disabled_reason: effectiveEnabled ? null : needsEnableTest ? "Pending worker SSH connection test." : "Disabled by administrator.",
      },
      prefer: "return=minimal",
    });

    if (previousRef?.startsWith("MANAGED:") && !nextRef?.startsWith("MANAGED:")) {
      await deleteManagedCredential(admin, targetId);
    }
    if (input.command_ids) {
      const existing = await admin.rest("target_commands", { query: `target_id=eq.${encodeURIComponent(targetId)}&select=command_id` });
      const previous = new Set(Array.isArray(existing) ? existing.filter(isRecord).map((row) => String(row.command_id)) : []);
      const next = new Set(input.command_ids);
      for (const commandId of next) {
        if (!previous.has(commandId)) await admin.rest("target_commands", { method: "POST", body: { target_id: targetId, command_id: commandId }, prefer: "return=minimal" });
      }
      for (const commandId of previous) {
        if (!next.has(commandId)) await admin.rest("target_commands", { method: "DELETE", query: `target_id=eq.${encodeURIComponent(targetId)}&command_id=eq.${encodeURIComponent(commandId)}`, prefer: "return=minimal" });
      }
    }
    await audit(admin, principal.id, "target.updated", targetId, {
      credential_source: input.credential_source,
      credential_replaced: hasManagedCredentialInput(input),
    });
    const connectionTest = needsEnableTest ? await queueConnectionTest(admin, principal.id, targetId, true) : null;
    return { ok: true, enabled: effectiveEnabled, connection_test: connectionTest };
  });

  server.post("/admin/api/v2/test-connection", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    throw new AppError(409, "saved_target_required", "Save the target as disabled before queuing its worker connection test.");
  });

  server.post("/admin/api/v2/targets/:id/test-connection", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    first(await admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=id&limit=1` }), "Target");
    const input = connectionTestInput.parse(request.body ?? {});
    const test = await queueConnectionTest(admin, principal.id, targetId, input.enable_on_success);
    return reply.code(202).send({ test });
  });

  server.get("/admin/api/v2/connection-tests/:id", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    return { test: first(await admin.rest("target_connection_tests", {
      query: `id=eq.${encodeURIComponent(idParam(request))}&select=*&limit=1`,
    }), "Connection test") };
  });

  server.post("/admin/api/v2/targets/:id/duplicate", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    const current = first<JsonRecord>(await admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=*&limit=1` }), "Target");
    const { id: _id, created_at: _createdAt, updated_at: _updatedAt, ...copy } = current;
    const sourceRef = typeof current.secret_ref === "string" ? current.secret_ref : null;
    const duplicateRef = sourceRef?.startsWith("MANAGED:") ? null : sourceRef;
    const assignments = await admin.rest("target_commands", { query: `target_id=eq.${encodeURIComponent(targetId)}&select=command_id` });
    const created = await admin.rest("targets", {
      method: "POST",
      body: { ...copy, secret_ref: duplicateRef, name: `${String(current.name)} copy`, enabled: false, created_by: principal.id, disabled_reason: "Duplicated target requires credential verification before activation." },
    });
    const row = first<JsonRecord>(created, "Target");
    const duplicateId = String(row.id);
    try {
      const commandIds = Array.isArray(assignments) ? assignments.filter(isRecord).map((assignment) => String(assignment.command_id)) : [];
      if (commandIds.length) {
        await admin.rest("target_commands", {
          method: "POST",
          body: commandIds.map((commandId) => ({ target_id: duplicateId, command_id: commandId })),
          prefer: "return=minimal",
        });
      }
      await audit(admin, principal.id, "target.duplicated", duplicateId, { source_target_id: targetId, managed_credential_copied: false, command_count: commandIds.length });
      return reply.code(201).send({ target: row });
    } catch (error) {
      await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(duplicateId)}`, prefer: "return=minimal" });
      throw error;
    }
  });

  server.delete("/admin/api/v2/targets/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    first(await admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=id&limit=1` }), "Target");
    await audit(admin, principal.id, "target.deletion_requested", targetId);
    try {
      await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(targetId)}`, prefer: "return=minimal" });
    } catch {
      await audit(admin, principal.id, "target.deletion_blocked", targetId, { reason: "Target has dependent history or could not be removed safely." });
      throw new AppError(409, "target_delete_blocked", "Target deletion was blocked. Disable it to preserve execution history, then retry after reviewing dependencies.");
    }
    await audit(admin, principal.id, "target.deleted", targetId);
    return reply.code(204).send();
  });
}
