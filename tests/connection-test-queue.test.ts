import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import type { AdminService } from "../src/admin.js";
import { registerImprovedTargetRoutes } from "../src/admin-targets-v2.js";
import { AppError } from "../src/errors.js";

const targetId = "00000000-0000-0000-0000-000000000010";
const testId = "00000000-0000-0000-0000-000000000011";

async function serverWithAdmin() {
  const calls: Array<{ table: string; options: Record<string, unknown> }> = [];
  const admin = {
    principal: async () => ({ id: "00000000-0000-0000-0000-000000000001", role: "admin" }),
    rest: async (table: string, options: Record<string, unknown> = {}) => {
      calls.push({ table, options });
      if (table === "targets" && options.method !== "PATCH") return [{ id: targetId }];
      if (table === "target_connection_tests" && options.method === "POST") {
        return [{ id: testId, target_id: targetId, status: "queued", enable_on_success: false }];
      }
      if (table === "target_connection_tests") return [];
      return [];
    },
  } as unknown as AdminService;
  const server = Fastify();
  server.setErrorHandler((error, _request, reply) => {
    if (error instanceof AppError) return reply.code(error.statusCode).send({ error: error.code });
    return reply.code(500).send({ error: "internal_error" });
  });
  registerImprovedTargetRoutes(server, admin);
  await server.ready();
  return { server, calls };
}

describe("worker connection-test queue", () => {
  it("queues a durable test for a saved target without running SSH in the web route", async () => {
    const { server, calls } = await serverWithAdmin();
    try {
      const response = await server.inject({
        method: "POST",
        url: `/admin/api/v2/targets/${targetId}/test-connection`,
        payload: {},
      });

      expect(response.statusCode).toBe(202);
      expect(response.json()).toMatchObject({ test: { id: testId, status: "queued" } });
      expect(calls).toContainEqual(expect.objectContaining({
        table: "target_connection_tests",
        options: expect.objectContaining({ method: "POST" }),
      }));
    } finally {
      await server.close();
    }
  });

  it("requires an encrypted, saved target before a worker test can be queued", async () => {
    const { server } = await serverWithAdmin();
    try {
      const response = await server.inject({ method: "POST", url: "/admin/api/v2/test-connection", payload: {} });
      expect(response.statusCode).toBe(409);
      expect(response.json()).toMatchObject({ error: "saved_target_required" });
    } finally {
      await server.close();
    }
  });
});
