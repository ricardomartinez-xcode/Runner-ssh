import { createHash } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { Environment } from "./config.js";

type Bucket = {
  count: number;
  resetAt: number;
};

function clientKey(request: { ip: string; headers: Record<string, unknown> }): string {
  const authorization = request.headers.authorization;
  if (typeof authorization === "string" && authorization) {
    return `user:${createHash("sha256").update(authorization).digest("base64url")}`;
  }
  return request.ip;
}

export function registerSecurity(server: FastifyInstance, env: Environment): void {
  const buckets = new Map<string, Bucket>();

  server.addHook("onRequest", async (request, reply) => {
    const now = Date.now();
    const key = clientKey(request);
    if (buckets.size > 10_000) {
      for (const [candidate, value] of buckets) {
        if (value.resetAt <= now) buckets.delete(candidate);
      }
    }
    if (buckets.size >= 20_000 && !buckets.has(key)) {
      return reply.code(429).send({ error: "rate_limited", message: "Rate-limit capacity reached. Try again after the current window." });
    }
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { count: 1, resetAt: now + env.RATE_LIMIT_WINDOW_MS });
    } else {
      bucket.count += 1;
      if (bucket.count > env.RATE_LIMIT_MAX) {
        return reply.code(429).send({ error: "rate_limited", message: "Too many requests. Try again later." });
      }
    }
  });

  server.addHook("onSend", async (request, reply, payload) => {
    const isBreakGlass = request.url.startsWith("/bash");
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    reply.header("Content-Security-Policy", (isBreakGlass ? [
      "default-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self'",
      "connect-src 'self' ws: wss:",
    ] : [
      "default-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self' https: wss:",
    ]).join("; "));
    if (request.url.startsWith("/admin") || request.url.startsWith("/bash")) {
      reply.header("Cache-Control", "no-store, max-age=0");
      reply.header("Pragma", "no-cache");
      reply.header("X-Robots-Tag", "noindex, nofollow");
    }
    return payload;
  });
}
