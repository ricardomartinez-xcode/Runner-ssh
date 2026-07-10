import Fastify, { type FastifyRequest } from "fastify";
import { z, ZodError } from "zod";
import type { Authenticator } from "./auth.js";
import { registerAdminRoutes, type AdminService } from "./admin.js";
import { registerExecutionRoutes } from "./admin-executions.js";
import { registerAdminUiRoutes } from "./admin-ui.js";
import type { Environment } from "./config.js";
import type { Principal } from "./types.js";
import { AppError, forbidden } from "./errors.js";
import type { Registry } from "./registry.js";
import type { Jobs } from "./jobs.js";

declare module "fastify" {
  interface FastifyRequest {
    principal?: Principal;
  }
}

const planBody = z.object({
  target_id: z.string().min(1),
  collection_id: z.string().min(1),
  task_id: z.string().min(1),
});

const confirmBody = z.object({ confirmation: z.literal("EJECUTAR") });

function path(request: FastifyRequest, key: string): string {
  const value = (request.params as Record<string, string | undefined>)[key];
  if (!value) throw new AppError(400, "bad_request", `Missing path parameter "${key}".`);
  return value;
}
function principal(request: FastifyRequest): Principal {
  if (!request.principal) throw new AppError(401, "unauthorized", "Authentication is required.");
  return request.principal;
}
function reader(request: FastifyRequest, env: Environment): Principal {
  const value = principal(request);
  if (![env.RUNNER_VIEWER_ROLE, env.RUNNER_OPERATOR_ROLE].some((role) => value.roles.includes(role))) {
    throw forbidden("Token is missing a runner reader role.");
  }
  return value;
}
function operator(request: FastifyRequest, env: Environment): Principal {
  const value = principal(request);
  if (!value.roles.includes(env.RUNNER_OPERATOR_ROLE)) throw forbidden("Token is missing runner.operator.");
  return value;
}

export function app(deps: { env: Environment; auth: Authenticator; registry: Registry; jobs: Jobs; admin: AdminService }) {
  const server = Fastify({
    logger: { level: process.env.LOG_LEVEL ?? "info", redact: ["req.headers.authorization"] },
  });

  server.setErrorHandler((error, _request, reply) => {
    if (error instanceof ZodError) return reply.code(400).send({ error: "bad_request", message: "Request validation failed.", details: error.flatten() });
    if (error instanceof AppError) return reply.code(error.statusCode).send({ error: error.code, message: error.message });
    server.log.error(error);
    return reply.code(500).send({ error: "internal_error", message: "Internal server error." });
  });

  server.get("/health", async () => ({ status: "ok", service: "relead-ops", admin: deps.admin.enabled ? "configured" : "disabled" }));

  server.addHook("onRequest", async (request, reply) => {
    if (request.url === "/admin" || request.url === "/admin/") return reply.redirect("/admin/manage");
    if (request.url === "/health" || request.url.startsWith("/admin")) return;
    request.principal = await deps.auth.verify(request.headers.authorization);
  });

  registerAdminRoutes(server, deps.admin);
  registerExecutionRoutes(server, deps.admin);
  registerAdminUiRoutes(server, deps.admin);

  server.get("/v1/collections", async (request) => ({ collections: deps.registry.listCollections(reader(request, deps.env)) }));
  server.get("/v1/collections/:collectionId", async (request) => deps.registry.getCollection(reader(request, deps.env), path(request, "collectionId")));
  server.get("/v1/targets", async (request) => ({ targets: deps.registry.listTargets(reader(request, deps.env)) }));
  server.get("/v1/targets/:targetId", async (request) => deps.registry.getTarget(reader(request, deps.env), path(request, "targetId")));

  server.post("/v1/jobs/plan", async (request, reply) => {
    const job = await deps.jobs.plan(operator(request, deps.env), planBody.parse(request.body));
    return reply.code(201).send({ ...job, next_step: 'Call confirmSshJob with confirmation "EJECUTAR".' });
  });
  server.post("/v1/jobs/:jobId/confirm", async (request) => deps.jobs.confirm(operator(request, deps.env), path(request, "jobId"), confirmBody.parse(request.body).confirmation));
  server.get("/v1/jobs/:jobId", async (request) => {
    const job = await deps.jobs.get(reader(request, deps.env), path(request, "jobId"));
    const { output: _output, ...summary } = job;
    return summary;
  });
  server.get("/v1/jobs/:jobId/log", async (request) => {
    const job = await deps.jobs.get(reader(request, deps.env), path(request, "jobId"));
    return { id: job.id, status: job.status, output: job.output, output_truncated: job.output_truncated, exit_code: job.exit_code, error: job.error };
  });
  server.post("/v1/jobs/:jobId/cancel", async (request) => deps.jobs.cancel(operator(request, deps.env), path(request, "jobId")));

  return server;
}
