import { readFile } from "node:fs/promises";
import YAML from "yaml";
import { z } from "zod";
import type { RunnerConfig, TargetDefinition } from "./types.js";

const secret = z.object({
  provider: z.enum(["1password", "env"]),
  reference: z.string().min(1),
  mode: z.enum(["key", "password", "private_key_password"]).optional(),
});

type JwtConfigSource = {
  SUPABASE_URL?: string;
  SUPABASE_JWKS_URL?: string;
  SUPABASE_JWT_AUDIENCE?: string;
  OIDC_ISSUER_URL?: string;
  OIDC_JWKS_URL?: string;
  OIDC_AUDIENCE?: string;
};

function optionalUrl() {
  return z.preprocess((value) => {
    if (typeof value !== "string") return value;
    const trimmed = value.trim();
    return trimmed || undefined;
  }, z.string().url().optional());
}

function optionalText() {
  return z.preprocess((value) => {
    if (typeof value !== "string") return value;
    const trimmed = value.trim();
    return trimmed || undefined;
  }, z.string().min(1).optional());
}

function booleanValue(defaultValue: boolean) {
  return z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return defaultValue;
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (["1", "true", "yes", "on"].includes(normalized)) return true;
      if (["0", "false", "no", "off"].includes(normalized)) return false;
    }
    return value;
  }, z.boolean());
}

export function resolveOidcConfig(source: JwtConfigSource): { issuerUrl?: string; jwksUrl?: string; audience?: string } {
  const supabaseUrl = source.SUPABASE_URL?.replace(/\/+$/, "");
  const hasSupabaseJwtConfig = Boolean(supabaseUrl || source.SUPABASE_JWKS_URL);
  return {
    issuerUrl: source.OIDC_ISSUER_URL ?? (supabaseUrl ? `${supabaseUrl}/auth/v1` : undefined),
    jwksUrl: source.OIDC_JWKS_URL ?? source.SUPABASE_JWKS_URL ?? (supabaseUrl ? `${supabaseUrl}/auth/v1/.well-known/jwks.json` : undefined),
    audience: source.OIDC_AUDIENCE ?? (hasSupabaseJwtConfig ? source.SUPABASE_JWT_AUDIENCE ?? "authenticated" : undefined),
  };
}

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
  type: z.enum(["ssh", "cloudflare_tunnel"]),
  host: z.string().regex(/^[A-Za-z0-9._:-]+$/),
  port: z.number().int().min(1).max(65535).default(22),
  username: z.string().regex(/^[A-Za-z0-9._-]+$/),
  known_hosts: z.string().min(1),
  auth: secret.extend({ mode: z.enum(["key", "password", "private_key_password"]) }),
});

const runnerConfig = z.object({
  version: z.literal(1),
  collections: z.record(collection).refine((value) => Object.keys(value).length > 0),
  targets: z.record(sshTarget).refine((value) => Object.keys(value).length > 0),
});

function csvValues(value: string | undefined): string[] {
  if (!value) return [];
  return [...new Set(value.split(",").map((entry) => entry.trim()).filter(Boolean))].sort();
}

function hasKnownHostEntry(value: string, host: string): boolean {
  return value.split(/\r?\n/).some((line) => {
    const [hosts, keyType, keyData] = line.trim().split(/\s+/);
    return Boolean(
      hosts?.split(",").includes(host)
      && keyType === "ssh-ed25519"
      && keyData
      && /^[A-Za-z0-9+/]+={0,2}$/.test(keyData),
    );
  });
}

const environment = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(10000),
  HOST: z.string().min(1).default("0.0.0.0"),
  DATA_DIR: z.string().min(1).default("/var/data"),
  RUNNER_CONFIG_PATH: z.string().min(1).default("/app/config/runner.yaml"),

  AUTH_MODE: z.enum(["oidc", "api_token", "dual", "clerk_oauth"]).default("oidc"),

  SUPABASE_URL: optionalUrl(),
  SUPABASE_JWKS_URL: optionalUrl(),
  SUPABASE_JWT_AUDIENCE: optionalText().default("authenticated"),

  OIDC_ISSUER_URL: optionalUrl(),
  OIDC_JWKS_URL: optionalUrl(),
  OIDC_AUDIENCE: optionalText(),
  OIDC_REQUIRED_SCOPE: z.string().optional().transform((value) => value === undefined ? "runner:ssh" : value.trim() || undefined),
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

  BREAK_GLASS_ENABLED: booleanValue(false),
  BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS: booleanValue(true),
  BREAK_GLASS_KEY_SHA256: z.string().regex(/^[a-fA-F0-9]{64}$/, "Must be a SHA-256 hex digest.").optional(),
  BREAK_GLASS_SESSION_SECRET: optionalText(),
  BREAK_GLASS_SESSION_TTL_SECONDS: z.coerce.number().int().min(300).max(1800).default(600),
  BREAK_GLASS_MAX_SESSION_BYTES: z.coerce.number().int().min(1_048_576).max(104_857_600).default(16_777_216),
  BREAK_GLASS_MAX_FAILED_ATTEMPTS: z.coerce.number().int().min(3).max(10).default(5),
  BREAK_GLASS_LOCKOUT_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  BREAK_GLASS_RENDER_PRIVATE_KEY: optionalText(),
  BREAK_GLASS_RENDER_SERVICE_ID: optionalText(),
  BREAK_GLASS_RENDER_SSH_HOST: optionalText(),
  BREAK_GLASS_RENDER_KNOWN_HOSTS: optionalText(),
  CLOUDFLARE_ACCESS_TEAM_DOMAIN: optionalUrl(),
  CLOUDFLARE_ACCESS_AUD: optionalText(),
}).superRefine((value, ctx) => {
  if (value.AUTH_MODE === "oidc" || value.AUTH_MODE === "dual") {
    const jwtConfig = resolveOidcConfig(value);
    ([
      ["OIDC_ISSUER_URL", jwtConfig.issuerUrl],
      ["OIDC_JWKS_URL", jwtConfig.jwksUrl],
      ["OIDC_AUDIENCE", jwtConfig.audience],
    ] as const).forEach(([key, candidate]) => {
      if (!candidate) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} is required when AUTH_MODE is ${value.AUTH_MODE}; set OIDC_* directly or configure SUPABASE_URL/SUPABASE_JWKS_URL.`,
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

  if (value.BREAK_GLASS_ENABLED) {
    const required = [
      ["BREAK_GLASS_KEY_SHA256", value.BREAK_GLASS_KEY_SHA256],
      ["BREAK_GLASS_SESSION_SECRET", value.BREAK_GLASS_SESSION_SECRET],
      ["BREAK_GLASS_RENDER_PRIVATE_KEY", value.BREAK_GLASS_RENDER_PRIVATE_KEY],
      ["BREAK_GLASS_RENDER_SERVICE_ID", value.BREAK_GLASS_RENDER_SERVICE_ID],
      ["BREAK_GLASS_RENDER_SSH_HOST", value.BREAK_GLASS_RENDER_SSH_HOST],
      ["BREAK_GLASS_RENDER_KNOWN_HOSTS", value.BREAK_GLASS_RENDER_KNOWN_HOSTS],
    ] as const;
    required.forEach(([key, candidate]) => {
      if (!candidate) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `${key} is required when BREAK_GLASS_ENABLED is true.` });
    });

    if (value.BREAK_GLASS_SESSION_SECRET && value.BREAK_GLASS_SESSION_SECRET.length < 32) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BREAK_GLASS_SESSION_SECRET"], message: "BREAK_GLASS_SESSION_SECRET must contain at least 32 characters." });
    }
    if (value.BREAK_GLASS_RENDER_SERVICE_ID && !/^srv-[a-z0-9]+(?:-[a-z0-9]{5})?$/.test(value.BREAK_GLASS_RENDER_SERVICE_ID)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BREAK_GLASS_RENDER_SERVICE_ID"], message: "BREAK_GLASS_RENDER_SERVICE_ID must be a Render service or instance id." });
    }
    if (value.BREAK_GLASS_RENDER_SSH_HOST && !/^ssh\.(oregon|ohio|virginia|frankfurt|singapore)\.render\.com$/.test(value.BREAK_GLASS_RENDER_SSH_HOST)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BREAK_GLASS_RENDER_SSH_HOST"], message: "BREAK_GLASS_RENDER_SSH_HOST must be an official Render SSH regional hostname." });
    }
    if (value.BREAK_GLASS_RENDER_SSH_HOST && value.BREAK_GLASS_RENDER_KNOWN_HOSTS && !hasKnownHostEntry(value.BREAK_GLASS_RENDER_KNOWN_HOSTS, value.BREAK_GLASS_RENDER_SSH_HOST)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BREAK_GLASS_RENDER_KNOWN_HOSTS"], message: "BREAK_GLASS_RENDER_KNOWN_HOSTS must contain the official ssh-ed25519 entry for the configured Render region." });
    }
    if (value.BREAK_GLASS_RENDER_PRIVATE_KEY && !/-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----/.test(value.BREAK_GLASS_RENDER_PRIVATE_KEY)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BREAK_GLASS_RENDER_PRIVATE_KEY"], message: "BREAK_GLASS_RENDER_PRIVATE_KEY must contain a supported private key." });
    }
    if (value.BREAK_GLASS_REQUIRE_CLOUDFLARE_ACCESS) {
      if (!value.CLOUDFLARE_ACCESS_TEAM_DOMAIN) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CLOUDFLARE_ACCESS_TEAM_DOMAIN"], message: "Cloudflare Access team domain is required for break-glass access." });
      if (!value.CLOUDFLARE_ACCESS_AUD) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CLOUDFLARE_ACCESS_AUD"], message: "Cloudflare Access application AUD is required for break-glass access." });
    }
    if (value.CLOUDFLARE_ACCESS_TEAM_DOMAIN && !/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com\/?$/i.test(value.CLOUDFLARE_ACCESS_TEAM_DOMAIN)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CLOUDFLARE_ACCESS_TEAM_DOMAIN"], message: "Cloudflare Access team domain must be an HTTPS cloudflareaccess.com origin without a path." });
    }
    if (value.CLOUDFLARE_ACCESS_AUD && !/^[A-Za-z0-9_-]{16,256}$/.test(value.CLOUDFLARE_ACCESS_AUD)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CLOUDFLARE_ACCESS_AUD"], message: "Cloudflare Access AUD has an invalid format." });
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
