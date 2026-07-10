import { readFile } from "node:fs/promises";
import YAML from "yaml";
import { z } from "zod";
import type { RunnerConfig, TargetDefinition } from "./types.js";

const secret = z.object({
  provider: z.enum(["1password", "env"]),
  reference: z.string().min(1),
  mode: z.enum(["key", "password", "token"]).optional(),
});

const task = z.object({
  description: z.string().min(1),
  argv: z.array(z.string().min(1)).min(1),
  timeout_seconds: z.number().int().min(1).max(3600).optional(),
});

const collection = z.object({
  description: z.string().min(1),
  required_roles: z.array(z.string().min(1)).optional(),
  tasks: z.record(task),
});

const targetBase = z.object({
  description: z.string().min(1),
  required_roles: z.array(z.string().min(1)).optional(),
  allowed_collections: z.array(z.string().min(1)).min(1),
  working_directory: z.string().min(1).optional(),
});

const sshTarget = targetBase.extend({
  type: z.literal("ssh"),
  host: z.string().regex(/^[A-Za-z0-9._:-]+$/),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().regex(/^[A-Za-z0-9._-]+$/),
  known_hosts: z.string().min(1),
  auth: secret.extend({ mode: z.enum(["key", "password"]) }),
});

const codespaceTarget = targetBase.extend({
  type: z.literal("codespace"),
  codespace_name: z.string().min(1).max(128),
  github_token: secret,
});

const runnerConfig = z.object({
  version: z.literal(1),
  collections: z.record(collection).refine((value) => Object.keys(value).length > 0),
  targets: z.record(z.union([sshTarget, codespaceTarget])).refine((value) => Object.keys(value).length > 0),
});

function csvValues(value: string | undefined): string[] {
  if (!value) return [];
  return [...new Set(value.split(",").map((entry) => entry.trim()).filter(Boolean))].sort();
}

const environment = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(10000),
  HOST: z.string().min(1).default("0.0.0.0"),
  DATA_DIR: z.string().min(1).default("/var/data"),
  RUNNER_CONFIG_PATH: z.string().min(1).default("/app/config/runner.yaml"),

  AUTH_MODE: z.enum(["oidc", "api_token", "dual", "clerk_oauth"]).default("oidc"),

  OIDC_ISSUER_URL: z.string().url().optional(),
  OIDC_JWKS_URL: z.string().url().optional(),
  OIDC_AUDIENCE: z.string().min(1).optional(),
  OIDC_REQUIRED_SCOPE: z.string().min(1).default("runner:ssh"),
  OIDC_ROLE_CLAIMS: z.string().min(1).default("roles,org_role"),

  CLERK_FRONTEND_API_URL: z.string().url().optional(),
  CLERK_OAUTH_CLIENT_ID: z.string().min(1).optional(),
  CLERK_OAUTH_CLIENT_SECRET: z.string().min(1).optional(),
  CLERK_REQUIRED_SCOPE: z.string().min(1).default("email"),
  CLERK_ROLE_CLAIMS: z.string().min(1).default("email"),

  RUNNER_API_TOKEN_SHA256: z.string().regex(/^[a-fA-F0-9]{64}$/, "Must be a SHA-256 hex digest.").optional(),
  RUNNER_API_TOKEN_ROLES: z.string().optional(),

  RUNNER_VIEWER_ROLE: z.string().min(1).default("runner.viewer"),
  RUNNER_OPERATOR_ROLE: z.string().min(1).default("runner.operator"),

  JOB_CONFIRMATION_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(600),
  MAX_JOB_DURATION_SECONDS: z.coerce.number().int().min(5).max(3600).default(300),
  MAX_LOG_BYTES: z.coerce.number().int().min(1024).max(1048576).default(65536),
  MAX_CONCURRENT_JOBS: z.coerce.number().int().min(1).max(10).default(2),

  WORKER_ID: z.string().min(1).default(`worker-${process.pid}`),
  WORKER_POLL_INTERVAL_MS: z.coerce.number().int().min(500).max(60_000).default(2500),
  WORKER_LOCK_SECONDS: z.coerce.number().int().min(30).max(900).default(90),
  WORKER_HEARTBEAT_INTERVAL_MS: z.coerce.number().int().min(1000).max(60_000).default(10_000),
  WORKER_STALE_SECONDS: z.coerce.number().int().min(60).max(3600).default(300),
  HEALTH_CHECK_INTERVAL_MS: z.coerce.number().int().min(30_000).max(86_400_000).default(300_000),

  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).max(3_600_000).default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().min(10).max(10_000).default(600),
}).superRefine((value, ctx) => {
  if (value.AUTH_MODE === "oidc" || value.AUTH_MODE === "dual") {
    ([
      ["OIDC_ISSUER_URL", value.OIDC_ISSUER_URL],
      ["OIDC_JWKS_URL", value.OIDC_JWKS_URL],
      ["OIDC_AUDIENCE", value.OIDC_AUDIENCE],
    ] as const).forEach(([key, candidate]) => {
      if (!candidate) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} is required when AUTH_MODE is ${value.AUTH_MODE}.`,
        });
      }
    });
  }

  if (value.AUTH_MODE === "clerk_oauth") {
    ([
      ["CLERK_FRONTEND_API_URL", value.CLERK_FRONTEND_API_URL],
      ["CLERK_OAUTH_CLIENT_ID", value.CLERK_OAUTH_CLIENT_ID],
      ["CLERK_OAUTH_CLIENT_SECRET", value.CLERK_OAUTH_CLIENT_SECRET],
    ] as const).forEach(([key, candidate]) => {
      if (!candidate) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} is required when AUTH_MODE is ${value.AUTH_MODE}.`,
        });
      }
    });
  }

  if (value.AUTH_MODE === "api_token" || value.AUTH_MODE === "dual") {
    if (!value.RUNNER_API_TOKEN_SHA256) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["RUNNER_API_TOKEN_SHA256"],
        message: `RUNNER_API_TOKEN_SHA256 is required when AUTH_MODE is ${value.AUTH_MODE}.`,
      });
    }

    if (csvValues(value.RUNNER_API_TOKEN_ROLES).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["RUNNER_API_TOKEN_ROLES"],
        message: `RUNNER_API_TOKEN_ROLES must contain at least one role when AUTH_MODE is ${value.AUTH_MODE}.`,
      });
    }
  }
});

export type Environment = z.infer<typeof environment>;

export function loadEnvironment(source: NodeJS.ProcessEnv = process.env): Environment {
  return environment.parse(source);
}

export async function loadRunnerConfig(path: string): Promise<RunnerConfig> {
  const parsed = runnerConfig.parse(YAML.parse(await readFile(path, "utf8")));
  for (const [targetId, target] of Object.entries(parsed.targets)) {
    for (const collectionId of target.allowed_collections) {
      if (!parsed.collections[collectionId]) {
        throw new Error(`Target "${targetId}" references missing collection "${collectionId}".`);
      }
    }
  }
  return {
    version: parsed.version,
    collections: parsed.collections,
    targets: parsed.targets as Record<string, TargetDefinition>,
  };
}
