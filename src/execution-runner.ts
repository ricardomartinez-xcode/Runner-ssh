import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AdminService } from "./admin.js";
import { AppError } from "./errors.js";
import { appendExecutionLog } from "./execution-log.js";
import { redact } from "./redaction.js";
import { readManagedCredential } from "./target-secrets.js";

export type JsonRecord = Record<string, unknown>;

export type TargetRow = {
  id: string;
  name: string;
  type: string;
  host: string;
  port: number;
  username: string;
  auth_type: "private_key" | "password" | "agent" | "token";
  secret_ref: string | null;
  working_directory: string | null;
  known_hosts: string | null;
  enabled: boolean;
  environment?: "prod" | "staging" | "dev";
};

export type CommandRow = {
  id: string;
  name: string;
  command_template: string;
  risk_level: "low" | "medium" | "high";
  requires_approval: boolean;
  allowed_roles: string[];
  enabled: boolean;
  destructive?: boolean;
  impact?: string | null;
};

export type SshExecutionResult = {
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  exitCode: number;
  durationMs: number;
  timedOut: boolean;
};

export type SshExecutionOptions = {
  timeoutMs: number;
  maxLogBytes: number;
  directCredential?: string;
  signal?: AbortSignal;
  onStdout?: (chunk: string, truncated: boolean) => Promise<void> | void;
  onStderr?: (chunk: string, truncated: boolean) => Promise<void> | void;
};

export function cloudflareProxyCommand(target: Pick<TargetRow, "type">): string | undefined {
  if (target.type !== "cloudflare_tunnel") return undefined;

  const clientId = process.env.CF_ACCESS_CLIENT_ID?.trim();
  const clientSecret = process.env.CF_ACCESS_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) {
    throw new AppError(
      500,
      "cloudflare_access_not_configured",
      "Cloudflare Access service-token credentials are missing.",
    );
  }

  return "cloudflared access ssh --hostname %h";
}

function quote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function renderedCommand(target: Pick<TargetRow, "working_directory">, commandTemplate: string): string {
  if (/[\u0000\r\n]/.test(commandTemplate)) {
    throw new AppError(400, "invalid_command_template", "Command templates cannot contain control characters or new lines.");
  }
  return target.working_directory ? `cd -- ${quote(target.working_directory)} && ${commandTemplate}` : commandTemplate;
}

export async function resolveExecutionSecret(admin: AdminService, reference: string | null): Promise<string | undefined> {
  if (!reference) return undefined;
  if (reference.startsWith("MANAGED:")) return readManagedCredential(admin, reference);
  const envName = reference.startsWith("RENDER_ENV:") ? reference.slice(11) : reference.startsWith("ENV:") ? reference.slice(4) : undefined;
  if (envName !== undefined) {
    if (!/^[A-Z_][A-Z0-9_]*$/.test(envName)) throw new AppError(400, "invalid_secret_ref", "Invalid environment secret reference.");
    const value = process.env[envName];
    if (!value) throw new AppError(500, "secret_resolution_failed", "Configured environment secret is missing.");
    return value;
  }
  if (reference.startsWith("1PASSWORD:")) {
    const opRef = reference.slice(10);
    if (!opRef.startsWith("op://")) throw new AppError(400, "invalid_secret_ref", "Invalid 1Password reference.");
    if (!process.env.OP_SERVICE_ACCOUNT_TOKEN) throw new AppError(500, "secret_resolution_failed", "1Password is not configured.");
    return await new Promise((resolve, reject) => {
      const child = spawn("op", ["read", opRef], { shell: false, stdio: ["ignore", "pipe", "ignore"] });
      let output = "";
      child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
      child.on("error", () => reject(new AppError(500, "secret_provider_unavailable", "1Password CLI is unavailable.")));
      child.on("close", (code) => code === 0 && output.trim() ? resolve(output.trim()) : reject(new AppError(500, "secret_resolution_failed", "Credential resolution failed.")));
    });
  }
  throw new AppError(400, "invalid_secret_ref", "Use a managed credential, a Render environment variable, or an advanced reference.");
}

export async function runSshCommand(
  admin: AdminService,
  target: TargetRow,
  commandText: string,
  options: SshExecutionOptions,
): Promise<SshExecutionResult> {
  if (!["ssh", "cloudflare_tunnel"].includes(target.type)) {
    throw new AppError(400, "unsupported_target", "This target type is not directly executable by the Render worker.");
  }
  if (!target.known_hosts?.trim()) throw new AppError(400, "known_hosts_required", "A known_hosts entry is required.");
  if (target.auth_type === "token") throw new AppError(400, "unsupported_auth", "Token authentication is not supported for SSH.");

  const directory = await mkdtemp(join(tmpdir(), "relead-ops-"));
  const knownHosts = join(directory, "known_hosts");
  const keyFile = join(directory, "identity");
  const credential = target.auth_type === "agent" ? undefined : options.directCredential ?? await resolveExecutionSecret(admin, target.secret_ref);
  await writeFile(knownHosts, `${target.known_hosts.trim()}\n`, { mode: 0o600 });
  if (target.auth_type === "private_key") {
    if (!credential) throw new AppError(500, "secret_resolution_failed", "Private key is missing.");
    await writeFile(keyFile, `${credential.trim()}\n`, { mode: 0o600 });
  }

  const args = [
    "-p", String(target.port),
    "-o", `BatchMode=${target.auth_type === "password" ? "no" : "yes"}`,
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${knownHosts}`,
    "-o", "ConnectTimeout=15",
    "-o", "LogLevel=ERROR",
  ];
  const proxyCommand = cloudflareProxyCommand(target);
  if (proxyCommand) args.push("-o", `ProxyCommand=${proxyCommand}`);
  if (target.auth_type === "private_key") args.push("-i", keyFile, "-o", "IdentitiesOnly=yes");
  args.push(`${target.username}@${target.host}`, commandText);

  const executable = target.auth_type === "password" ? "sshpass" : "ssh";
  const finalArgs = target.auth_type === "password" ? ["-e", "ssh", ...args] : args;
  const env = target.auth_type === "password" ? { ...process.env, SSHPASS: credential ?? "" } : process.env;
  const started = Date.now();

  try {
    return await new Promise((resolve, reject) => {
      const child = spawn(executable, finalArgs, { shell: false, env, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      let stdoutTruncated = false;
      let stderrTruncated = false;
      let timedOut = false;
      let finished = false;
      const stop = () => {
        if (child.exitCode !== null || child.killed) return;
        timedOut = true;
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      };
      const timer = setTimeout(stop, options.timeoutMs);
      const abort = () => {
        if (child.exitCode !== null || child.killed) return;
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      };
      options.signal?.addEventListener("abort", abort, { once: true });

      child.stdout.on("data", (chunk: Buffer) => {
        const next = appendExecutionLog(stdout, chunk.toString("utf8"), options.maxLogBytes);
        stdout = next.value;
        stdoutTruncated ||= next.truncated;
        void options.onStdout?.(redact(chunk.toString("utf8")), stdoutTruncated);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        const next = appendExecutionLog(stderr, chunk.toString("utf8"), options.maxLogBytes);
        stderr = next.value;
        stderrTruncated ||= next.truncated;
        void options.onStderr?.(redact(chunk.toString("utf8")), stderrTruncated);
      });
      child.on("error", () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", abort);
        reject(new AppError(500, "ssh_unavailable", "SSH client could not be started."));
      });
      child.on("close", (code) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        options.signal?.removeEventListener("abort", abort);
        resolve({
          stdout,
          stderr,
          stdoutTruncated,
          stderrTruncated,
          exitCode: code ?? 255,
          durationMs: Date.now() - started,
          timedOut,
        });
      });
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export function commandFromRow(target: TargetRow, command: Pick<CommandRow, "command_template">): string {
  return renderedCommand(target, command.command_template);
}
