import Fastify from "fastify";
import { describe, expect, it } from "vitest";
import { loadEnvironment } from "../src/config.js";
import { registerSecurity } from "../src/security.js";

describe("HTTP security controls", () => {
  it("does not let forwarded IP headers bypass anonymous rate limiting", async () => {
    const server = Fastify();
    const env = loadEnvironment({
      AUTH_MODE: "api_token",
      RUNNER_API_TOKEN_SHA256: "a".repeat(64),
      RUNNER_API_TOKEN_ROLES: "runner.operator",
      RATE_LIMIT_MAX: "10",
      RATE_LIMIT_WINDOW_MS: "60000",
    });
    registerSecurity(server, env);
    server.get("/probe", async () => ({ ok: true }));
    await server.ready();

    try {
      for (let requestNumber = 0; requestNumber < 10; requestNumber += 1) {
        const response = await server.inject({
          method: "GET",
          url: "/probe",
          headers: {
            "cf-connecting-ip": `198.51.100.${requestNumber + 1}`,
            "x-forwarded-for": `203.0.113.${requestNumber + 1}`,
          },
        });
        expect(response.statusCode).toBe(200);
      }

      const limited = await server.inject({
        method: "GET",
        url: "/probe",
        headers: { "cf-connecting-ip": "192.0.2.99" },
      });
      expect(limited.statusCode).toBe(429);
    } finally {
      await server.close();
    }
  });
});
