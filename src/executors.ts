import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Plan, SshTarget } from "./types.js";
import type { SecretResolver } from "./secrets.js";
import { run, type ProcessResult } from "./process.js";

function quote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function remoteCommand(plan: Plan): string {
  const command = plan.task.argv.map(quote).join(" ");
  return plan.target.working_directory
    ? `cd ${quote(plan.target.working_directory)} && exec ${command}`
    : `exec ${command}`;
}

export class Executors {
  constructor(private readonly secrets: SecretResolver) {}

  async execute(plan: Plan, signal: AbortSignal, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    return plan.target.type === "ssh"
      ? this.ssh(plan, signal, timeoutMs, maxOutputBytes)
      : this.codespace(plan, signal, timeoutMs, maxOutputBytes);
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
      if (target.auth.mode === "key") {
        const keyPath = join(directory, "id_key");
        const key = await this.secrets.read(target.auth);
        await writeFile(keyPath, `${key.trim()}\n`, { mode: 0o600 });
        await chmod(keyPath, 0o600);
        return run("ssh", [...common, "-i", keyPath, `${target.username}@${target.host}`, remoteCommand(plan)], {
          env: process.env, timeoutMs, maxOutputBytes, signal,
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
        env: { ...process.env, SSHPASS: password }, timeoutMs, maxOutputBytes, signal,
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  private async codespace(plan: Plan, signal: AbortSignal, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    if (plan.target.type !== "codespace") throw new Error("Wrong executor.");
    const home = await mkdtemp(join(tmpdir(), "runner-gh-"));
    try {
      const token = await this.secrets.read(plan.target.github_token);
      return run("gh", ["codespace", "ssh", "-c", plan.target.codespace_name, "--", remoteCommand(plan)], {
        env: { ...process.env, GH_TOKEN: token, GH_CONFIG_DIR: join(home, "gh"), HOME: home },
        timeoutMs, maxOutputBytes, signal,
      });
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  }
}
