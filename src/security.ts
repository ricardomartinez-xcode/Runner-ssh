import type { FastifyInstance } from "fastify";
import type { Environment } from "./config.js";

type Bucket = {
  count: number;
  resetAt: number;
};

function clientKey(request: { ip: string; headers: Record<string, unknown> }): string {
  const forwarded = request.headers["cf-connecting-ip"] ?? request.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim()) return forwarded.split(",")[0]?.trim() ?? request.ip;
  return request.ip;
}

export function registerSecurity(server: FastifyInstance, env: Environment): void {
  const buckets = new Map<string, Bucket>();

  server.addHook("onRequest", async (request, reply) => {
    const now = Date.now();
    const key = `${clientKey(request)}:${request.headers.authorization ? "auth" : "anon"}`;
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
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    reply.header("Content-Security-Policy", [
      "default-src 'self'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self' https:",
    ].join("; "));
    if (request.url.startsWith("/admin")) {
      reply.header("Cache-Control", "no-store, max-age=0");
      reply.header("Pragma", "no-cache");
      reply.header("X-Robots-Tag", "noindex, nofollow");
    }
    return payload;
  });
}
