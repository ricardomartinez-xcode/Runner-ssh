import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Plan, SshTarget } from "./types.js";
import type { SecretResolver } from "./secrets.js";
import { run, type ProcessResult } from "./process.js";
import { cloudflareAccessEnvironment } from "./execution-runner.js";

function quote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function remoteCommand(plan: Plan): string {
  const command = plan.task.argv.map(quote).join(" ");
  return plan.target.working_directory
    ? `cd ${quote(plan.target.working_directory)} && exec ${command}`
    : `exec ${command}`;
}

function combinedCredential(value: string): { privateKey: string; password: string } {
  try {
    const parsed = JSON.parse(value) as { private_key?: unknown; privateKey?: unknown; password?: unknown };
    const privateKey = typeof parsed.private_key === "string" ? parsed.private_key : parsed.privateKey;
    if (typeof privateKey === "string" && typeof parsed.password === "string" && privateKey.trim() && parsed.password) {
      return { privateKey, password: parsed.password };
    }
  } catch {
    // Fall through to the explicit validation error below.
  }
  throw new Error("private_key_password credentials must be JSON with private_key and password.");
}

export class Executors {
  constructor(private readonly secrets: SecretResolver) {}

  async execute(plan: Plan, signal: AbortSignal, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    return this.ssh(plan, signal, timeoutMs, maxOutputBytes);
  }

  private async ssh(plan: Plan, signal: AbortSignal, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    const target = plan.target as SshTarget;
    const directory = await mkdtemp(join(tmpdir(), "runner-ssh-"));
    const knownHosts = join(directory, "known_hosts");
    try {
      await writeFile(knownHosts, `${target.known_hosts.trim()}\n`, { mode: 0o600 });
      const common = [
        "-o", "StrictHostKeyChecking=yes",
        "-o", `UserKnownHostsFile=${knownHosts}`,
        "-o", "IdentitiesOnly=yes",
        "-o", "LogLevel=ERROR",
        "-p", String(target.port ?? 22),
      ];
      if (target.type === "cloudflare_tunnel") {
        common.push("-o", "ProxyCommand=cloudflared access ssh --hostname %h");
      }
      const baseEnvironment = target.type === "cloudflare_tunnel"
        ? { ...process.env, ...cloudflareAccessEnvironment() }
        : process.env;
      if (target.auth.mode === "key" || target.auth.mode === "private_key_password") {
        const keyPath = join(directory, "id_key");
        const credential = await this.secrets.read(target.auth);
        const combined = target.auth.mode === "private_key_password" ? combinedCredential(credential) : undefined;
        const key = combined?.privateKey ?? credential;
        await writeFile(keyPath, `${key.trim()}\n`, { mode: 0o600 });
        await chmod(keyPath, 0o600);
        if (combined) {
          return run("sshpass", [
            "-e", "ssh", ...common, "-i", keyPath,
            "-o", "BatchMode=no",
            "-o", "PreferredAuthentications=publickey,password,keyboard-interactive",
            `${target.username}@${target.host}`,
            remoteCommand(plan),
          ], {
            env: { ...baseEnvironment, SSHPASS: combined.password }, timeoutMs, maxOutputBytes, signal,
          });
        }
        return run("ssh", [...common, "-i", keyPath, `${target.username}@${target.host}`, remoteCommand(plan)], {
          env: baseEnvironment, timeoutMs, maxOutputBytes, signal,
        });
      }
      const password = await this.secrets.read(target.auth);
      return run("sshpass", [
        "-e", "ssh", ...common,
        "-o", "BatchMode=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        `${target.username}@${target.host}`,
        remoteCommand(plan),
      ], {
        env: { ...baseEnvironment, SSHPASS: password }, timeoutMs, maxOutputBytes, signal,
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
}
