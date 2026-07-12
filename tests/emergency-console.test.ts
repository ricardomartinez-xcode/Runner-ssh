import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import websocket from "@fastify/websocket";
import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { AdminService } from "../src/admin.js";
import { loadEnvironment } from "../src/config.js";
import { registerEmergencyConsoleRoutes } from "../src/emergency-console.js";
import { AppError } from "../src/errors.js";

const recoveryKey = "test-recovery-key-with-enough-entropy";
const recoveryHash = createHash("sha256").update(recoveryKey).digest("hex");

async function testServer(enabled = true, requireAccess = false) {
  const dataDir = await mkdtemp(join(tmpdir(), "relead-break-glass-test-"));
  const env = loadEnvironment({
    AUTH_MODE: "api_token",
    RUNNER_API_TOKEN_SHA256: "a".repeat(64),
    RUNNER_API_TOKEN_ROLES: "runner.operator",
    DATA_DIR: dataDir,
    BREAK_GLASS_ENABLED: String(enabled),
    BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS: String(requireAccess),
    ...(enabled ? {
      BREAK_GLASS_KEY_SHA256: recoveryHash,
      BREAK_GLASS_SESSION_SECRET: "test-session-secret-with-at-least-32-characters",
      BREAK_GLASS_RENDER_PRIVATE_KEY: "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
      BREAK_GLASS_RENDER_SERVICE_ID: "srv-abc123",
      BREAK_GLASS_RENDER_SSH_HOST: "ssh.oregon.render.com",
      BREAK_GLASS_RENDER_KNOWN_HOSTS: "ssh.oregon.render.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
      ...(requireAccess ? {
        CLOUDFLARE_ACCESS_TEAM_DOMAIN: "https://relead-test.cloudflareaccess.com",
        CLOUDFLARE_ACCESS_AUD: "test-access-audience",
      } : {}),
    } : {}),
  });
  const admin = {
    enabled: false,
    principal: async () => { throw new Error("Supabase admin authentication must not be used by /bash."); },
  } as unknown as AdminService;
  const server = Fastify();
  server.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    return reply.code(500).send({ error: "internal_error" });
  });
  void server.register(websocket, { options: { maxPayload: 64 * 1024 } });
  void server.register(async (scope) => {
    registerEmergencyConsoleRoutes(scope, admin, env);
  });
  await server.ready();
  return { server, dataDir };
}

describe("break-glass recovery console", () => {
  it("is independent from the Supabase admin panel", async () => {
    const { server, dataDir } = await testServer();
    try {
      const response = await server.inject({ method: "GET", url: "/bash" });
      expect(response.statusCode).toBe(200);
      expect(response.body).toContain("Consola break-glass del worker en Render");
      expect(response.body).toContain("Clave de recuperación");
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("rejects an invalid recovery key and writes a local audit event", async () => {
    const { server, dataDir } = await testServer();
    try {
      const response = await server.inject({ method: "POST", url: "/bash/auth", payload: { key: "wrong-recovery-key-with-enough-length" } });
      expect(response.statusCode).toBe(401);
      expect(await readFile(join(dataDir, "break-glass-audit.jsonl"), "utf8")).toContain("break_glass.authentication_failed");
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("does not let forwarded IP headers bypass the recovery lockout", async () => {
    const { server, dataDir } = await testServer();
    try {
      for (let attempt = 0; attempt < 5; attempt += 1) {
        const response = await server.inject({
          method: "POST",
          url: "/bash/auth",
          headers: { "cf-connecting-ip": `198.51.100.${attempt + 1}`, "x-forwarded-for": `203.0.113.${attempt + 1}` },
          payload: { key: "wrong-recovery-key-with-enough-length" },
        });
        expect(response.statusCode).toBe(401);
      }

      const locked = await server.inject({
        method: "POST",
        url: "/bash/auth",
        headers: { "cf-connecting-ip": "192.0.2.50" },
        payload: { key: recoveryKey },
      });
      expect(locked.statusCode).toBe(423);
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("issues a short-lived, bound recovery session for the correct key", async () => {
    const { server, dataDir } = await testServer();
    try {
      const auth = await server.inject({ method: "POST", url: "/bash/auth", payload: { key: recoveryKey } });
      expect(auth.statusCode).toBe(200);
      expect(auth.json()).toMatchObject({ socket_ticket: expect.any(String), expires_at: expect.any(String) });
      const cookie = String(auth.headers["set-cookie"]).split(";")[0];
      expect(cookie).toContain("relead_break_glass=");
      expect(String(auth.headers["set-cookie"])).toContain("HttpOnly");
      expect(String(auth.headers["set-cookie"])).toContain("SameSite=Strict");

      const session = await server.inject({ method: "GET", url: "/bash/session", headers: { cookie } });
      expect(session.json()).toMatchObject({ authenticated: true });
      expect(session.json()).not.toHaveProperty("socket_ticket");
      expect(await readFile(join(dataDir, "break-glass-audit.jsonl"), "utf8")).toContain("break_glass.authenticated");
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("does not open a recovery socket with only the session cookie", async () => {
    const { server, dataDir } = await testServer();
    try {
      const auth = await server.inject({
        method: "POST",
        url: "/bash/auth",
        headers: { "cf-connecting-ip": "198.51.100.10" },
        payload: { key: recoveryKey },
      });
      const cookie = String(auth.headers["set-cookie"]).split(";")[0];
      const socket = await server.injectWS("/bash/socket", {
        headers: { cookie, "cf-connecting-ip": "198.51.100.10" },
        socket: { remoteAddress: "127.0.0.1" } as never,
      });
      const closed = new Promise<{ code: number; reason: string }>((resolve) => {
        socket.once("close", (code, reason) => resolve({ code, reason: reason.toString() }));
      });
      socket.send(JSON.stringify({ type: "authorize", ticket: "x".repeat(32) }));
      await expect(closed).resolves.toMatchObject({ code: 1008, reason: "Invalid recovery ticket" });
      expect(await readFile(join(dataDir, "break-glass-audit.jsonl"), "utf8")).toContain("break_glass.socket_authorization_failed");
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("returns not found while break-glass access is disabled", async () => {
    const { server, dataDir } = await testServer(false);
    try {
      const response = await server.inject({ method: "GET", url: "/bash" });
      expect(response.statusCode).toBe(404);
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it("fails closed when Cloudflare Access is required but its assertion is absent", async () => {
    const { server, dataDir } = await testServer(true, true);
    try {
      const response = await server.inject({ method: "GET", url: "/bash" });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({ error: "access_required" });
    } finally {
      await server.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });
});
