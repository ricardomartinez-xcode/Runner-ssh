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

const environment = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(10000),
  HOST: z.string().min(1).default("0.0.0.0"),
  DATA_DIR: z.string().min(1).default("/var/data"),
  RUNNER_CONFIG_PATH: z.string().min(1).default("/app/config/runner.yaml"),
  OIDC_ISSUER_URL: z.string().url(),
  OIDC_JWKS_URL: z.string().url(),
  OIDC_AUDIENCE: z.string().min(1),
  OIDC_REQUIRED_SCOPE: z.string().min(1).default("runner:ssh"),
  RUNNER_VIEWER_ROLE: z.string().min(1).default("runner.viewer"),
  RUNNER_OPERATOR_ROLE: z.string().min(1).default("runner.operator"),
  JOB_CONFIRMATION_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(600),
  MAX_JOB_DURATION_SECONDS: z.coerce.number().int().min(5).max(3600).default(300),
  MAX_LOG_BYTES: z.coerce.number().int().min(1024).max(1048576).default(65536),
  MAX_CONCURRENT_JOBS: z.coerce.number().int().min(1).max(10).default(2),
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
