import { spawn } from "node:child_process";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AdminService } from "./admin.js";
import { AppError, forbidden } from "./errors.js";
import { runSshCommand, type TargetRow } from "./execution-runner.js";
import { availableTargetTypes, normalizeCredentialReference, validateTargetCredential } from "./target-onboarding.js";
import { deleteManagedCredential, managedCredentialsEnabled, storeManagedCredential } from "./target-secrets.js";

type JsonRecord = Record<string, unknown>;

const targetInput = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ssh", "cloudflare_tunnel"]),
  host: z.string().min(1).max(255),
  port: z.coerce.number().int().min(1).max(65535).default(22),
  username: z.string().min(1).max(120),
  auth_type: z.enum(["private_key", "password", "agent"]).default("private_key"),
  credential_source: z.enum(["managed", "environment", "agent", "reference"]).default("managed"),
  credential: z.string().max(50_000).optional(),
  credential_confirmation: z.string().max(50_000).optional(),
  environment_variable: z.string().max(120).optional(),
  secret_reference: z.string().max(500).optional(),
  tags: z.array(z.string().min(1).max(50)).max(20).default([]),
  environment: z.enum(["prod", "staging", "dev"]).default("dev"),
  working_directory: z.string().max(500).nullable().optional(),
  known_hosts: z.string().max(10_000).nullable().optional(),
  enabled: z.boolean().default(true),
});

const scanInput = z.object({
  host: z.string().min(1).max(255).regex(/^[A-Za-z0-9._:[\]-]+$/, "Invalid host."),
  port: z.coerce.number().int().min(1).max(65535).default(22),
});

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
    return { managed_credentials_enabled: managedCredentialsEnabled(), target_types: availableTargetTypes() };
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
    validateTargetCredential({
      authType: input.auth_type,
      source: input.credential_source,
      credential: input.credential,
      credentialConfirmation: input.credential_confirmation,
    });

    const created = await admin.rest("targets", {
      method: "POST",
      body: { ...targetRecord(input, initialRef), created_by: principal.id },
    });
    const row = first(created, "Target");
    const targetId = String(row.id);

    try {
      if (input.credential_source === "managed") {
        const managedRef = await storeManagedCredential(admin, targetId, input.credential ?? "", principal.id);
        await admin.rest("targets", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(targetId)}`,
          body: { secret_ref: managedRef },
          prefer: "return=minimal",
        });
        row.secret_ref = managedRef;
      }
      await audit(admin, principal.id, "target.created", targetId, {
        name: input.name,
        type: input.type,
        credential_source: input.credential_source,
      });
      return reply.code(201).send({ target: row });
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
    if (input.credential_source === "managed") {
      if (input.credential?.trim()) {
        validateTargetCredential({
          authType: input.auth_type,
          source: input.credential_source,
          credential: input.credential,
          credentialConfirmation: input.credential_confirmation,
        });
        nextRef = await storeManagedCredential(admin, targetId, input.credential, principal.id);
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

    await admin.rest("targets", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(targetId)}`,
      body: targetRecord(input, nextRef),
      prefer: "return=minimal",
    });

    if (previousRef?.startsWith("MANAGED:") && !nextRef?.startsWith("MANAGED:")) {
      await deleteManagedCredential(admin, targetId);
    }
    await audit(admin, principal.id, "target.updated", targetId, {
      credential_source: input.credential_source,
      credential_replaced: Boolean(input.credential?.trim()),
    });
    return { ok: true };
  });

  server.post("/admin/api/v2/test-connection", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const input = targetInput.parse(request.body);
    validateTargetCredential({
      authType: input.auth_type,
      source: input.credential_source,
      credential: input.credential,
      credentialConfirmation: input.credential_confirmation,
    });
    const secretRef = normalizeCredentialReference({
      source: input.credential_source,
      environmentVariable: input.environment_variable,
      secretReference: input.secret_reference,
    });
    const target: TargetRow = {
      id: "pending",
      name: input.name,
      type: input.type,
      host: input.host,
      port: input.port,
      username: input.username,
      auth_type: input.credential_source === "agent" ? "agent" : input.auth_type,
      secret_ref: secretRef,
      tags: input.tags,
      working_directory: input.working_directory ?? null,
      known_hosts: input.known_hosts ?? null,
      enabled: input.enabled,
      environment: input.environment,
    } as TargetRow;
    const result = await runSshCommand(admin, target, "whoami && hostname && uptime", {
      timeoutMs: 60_000,
      maxLogBytes: 16_384,
      directCredential: input.credential_source === "managed" ? input.credential : undefined,
    });
    return { ok: result.exitCode === 0, exit_code: result.exitCode, stdout: result.stdout, stderr: result.stderr, duration_ms: result.durationMs };
  });

  server.post("/admin/api/v2/targets/:id/test-connection", async (request) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    const target = first<TargetRow>(await admin.rest("targets", {
      query: `id=eq.${encodeURIComponent(targetId)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled,environment&limit=1`,
    }), "Target");
    try {
      const result = await runSshCommand(admin, target, "whoami && hostname && uptime", { timeoutMs: 60_000, maxLogBytes: 16_384 });
      await admin.rest("targets", {
        method: "PATCH",
        query: `id=eq.${encodeURIComponent(targetId)}`,
        body: { last_tested_at: new Date().toISOString(), last_test_status: result.exitCode === 0 ? "passed" : "failed", last_test_message: result.exitCode === 0 ? "Connection test passed." : result.stderr || "Connection test failed." },
        prefer: "return=minimal",
      });
      await audit(admin, principal.id, "target.connection_tested", targetId, { exit_code: result.exitCode, duration_ms: result.durationMs });
      return { ok: result.exitCode === 0, exit_code: result.exitCode, stdout: result.stdout, stderr: result.stderr, duration_ms: result.durationMs };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Connection test failed.";
      await admin.rest("targets", {
        method: "PATCH",
        query: `id=eq.${encodeURIComponent(targetId)}`,
        body: { last_tested_at: new Date().toISOString(), last_test_status: "failed", last_test_message: message },
        prefer: "return=minimal",
      });
      throw error;
    }
  });

  server.post("/admin/api/v2/targets/:id/duplicate", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    const current = first<JsonRecord>(await admin.rest("targets", { query: `id=eq.${encodeURIComponent(targetId)}&select=*&limit=1` }), "Target");
    const { id: _id, created_at: _createdAt, updated_at: _updatedAt, ...copy } = current;
    const created = await admin.rest("targets", {
      method: "POST",
      body: { ...copy, name: `${String(current.name)} copy`, enabled: false, created_by: principal.id, disabled_reason: "Duplicated target requires verification before activation." },
    });
    const row = first<JsonRecord>(created, "Target");
    await audit(admin, principal.id, "target.duplicated", String(row.id), { source_target_id: targetId });
    return reply.code(201).send({ target: row });
  });

  server.delete("/admin/api/v2/targets/:id", async (request, reply) => {
    const principal = await admin.principal(request);
    requireAdmin(principal.role);
    const targetId = idParam(request);
    await admin.rest("targets", { method: "DELETE", query: `id=eq.${encodeURIComponent(targetId)}`, prefer: "return=minimal" });
    await audit(admin, principal.id, "target.deleted", targetId);
    return reply.code(204).send();
  });
}
