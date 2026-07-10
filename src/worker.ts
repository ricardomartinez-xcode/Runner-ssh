import type { AdminService } from "./admin.js";
import type { Environment } from "./config.js";
import { AppError } from "./errors.js";
import { commandFromRow, runSshCommand, type CommandRow, type JsonRecord, type TargetRow } from "./execution-runner.js";
import { redact } from "./redaction.js";
import { nextRetryPatch, workerHeartbeatPatch } from "./worker-state.js";

type ExecutionRow = JsonRecord & {
  id: string;
  target_id: string;
  command_id: string;
  retry_count?: number | null;
  max_retries?: number | null;
};

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function first<T>(value: unknown, label: string): T {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0] as T;
}

async function audit(admin: AdminService, action: string, executionId: string, metadata: JsonRecord = {}): Promise<void> {
  await admin.rest("audit_logs", {
    method: "POST",
    body: { action, entity_type: "execution", entity_id: executionId, metadata },
    prefer: "return=minimal",
  });
}

async function executionContext(admin: AdminService, execution: ExecutionRow): Promise<{ target: TargetRow; command: CommandRow }> {
  const [targetValue, commandValue] = await Promise.all([
    admin.rest("targets", {
      query: `id=eq.${encodeURIComponent(execution.target_id)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled,environment&limit=1`,
    }),
    admin.rest("commands", {
      query: `id=eq.${encodeURIComponent(execution.command_id)}&select=id,name,command_template,risk_level,requires_approval,allowed_roles,enabled,destructive,impact&limit=1`,
    }),
  ]);
  const target = first<TargetRow>(targetValue, "Target");
  const command = first<CommandRow>(commandValue, "Command");
  if (!target.enabled) throw new AppError(409, "target_disabled", "Target is disabled.");
  if (!command.enabled) throw new AppError(409, "command_disabled", "Command is disabled.");
  return { target, command };
}

async function appendEvent(admin: AdminService, executionId: string, stream: "stdout" | "stderr" | "system", chunk: string, truncated = false): Promise<void> {
  await admin.rest("execution_log_events", {
    method: "POST",
    body: {
      execution_id: executionId,
      stream,
      chunk: redact(chunk).slice(0, 16_384),
      redacted: true,
      truncated,
    },
    prefer: "return=minimal",
  });
}

async function patchExecution(admin: AdminService, id: string, body: JsonRecord): Promise<void> {
  await admin.rest("executions", {
    method: "PATCH",
    query: `id=eq.${encodeURIComponent(id)}`,
    body,
    prefer: "return=minimal",
  });
}

export async function claimExecution(admin: AdminService, env: Environment): Promise<ExecutionRow | null> {
  const rows = await admin.rpc("claim_execution", {
    p_worker_id: env.WORKER_ID,
    p_lock_seconds: env.WORKER_LOCK_SECONDS,
  });
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return first<ExecutionRow>(rows, "Execution");
}

export async function runClaimedExecution(admin: AdminService, env: Environment, execution: ExecutionRow): Promise<void> {
  let heartbeat: NodeJS.Timeout | undefined;
  try {
    await appendEvent(admin, execution.id, "system", `Worker ${env.WORKER_ID} started execution.\n`);
    heartbeat = setInterval(() => {
      void patchExecution(admin, execution.id, workerHeartbeatPatch(env.WORKER_ID, new Date()));
    }, env.WORKER_HEARTBEAT_INTERVAL_MS);

    const { target, command } = await executionContext(admin, execution);
    const result = await runSshCommand(admin, target, commandFromRow(target, command), {
      timeoutMs: env.MAX_JOB_DURATION_SECONDS * 1000,
      maxLogBytes: env.MAX_LOG_BYTES,
      onStdout: (chunk, truncated) => appendEvent(admin, execution.id, "stdout", chunk, truncated),
      onStderr: (chunk, truncated) => appendEvent(admin, execution.id, "stderr", chunk, truncated),
    });
    const status = result.exitCode === 0 && !result.timedOut ? "succeeded" : "failed";
    await patchExecution(admin, execution.id, {
      status,
      stdout: result.stdout,
      stderr: result.stderr,
      stdout_truncated: result.stdoutTruncated,
      stderr_truncated: result.stderrTruncated,
      exit_code: result.exitCode,
      duration_ms: result.durationMs,
      error: result.timedOut ? "Task timed out." : status === "failed" ? "Task exited with a non-zero code." : null,
      last_error: result.timedOut ? "Task timed out." : status === "failed" ? "Task exited with a non-zero code." : null,
      finished_at: new Date().toISOString(),
      locked_at: null,
      heartbeat_at: null,
      worker_id: null,
    });
    await appendEvent(admin, execution.id, "system", `Execution ${status} with exit code ${result.exitCode}.\n`);
    await audit(admin, `execution.${status}`, execution.id, { exit_code: result.exitCode, duration_ms: result.durationMs, worker_id: env.WORKER_ID });
  } catch (error) {
    const message = redact(error instanceof Error ? error.message : "Worker execution failed.");
    const patch = nextRetryPatch({
      retry_count: typeof execution.retry_count === "number" ? execution.retry_count : 0,
      max_retries: typeof execution.max_retries === "number" ? execution.max_retries : 2,
    }, message, new Date());
    await patchExecution(admin, execution.id, { ...patch, error: patch.status === "failed" ? message : null });
    await appendEvent(admin, execution.id, "system", `${message}\n`, false);
    await audit(admin, patch.status === "failed" ? "execution.failed" : "execution.retry_queued", execution.id, { error: message, worker_id: env.WORKER_ID });
  } finally {
    if (heartbeat) clearInterval(heartbeat);
  }
}

export async function runHealthChecks(admin: AdminService, env: Environment): Promise<void> {
  const rows = await admin.rest("targets", {
    query: "enabled=eq.true&type=in.(ssh,cloudflare_tunnel)&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled,environment&order=created_at.asc&limit=100",
  });
  if (!Array.isArray(rows)) return;
  for (const row of rows) {
    if (!isRecord(row)) continue;
    const target = row as TargetRow;
    const started = Date.now();
    try {
      const result = await runSshCommand(admin, target, [
        "printf 'hostname='; hostname",
        "printf 'uptime='; uptime",
        "free | awk '/Mem:/ {printf \"ram_percent=%d\\n\", ($3/$2)*100}'",
        "df -P / | awk 'NR==2 {gsub(\"%\",\"\",$5); print \"disk_percent=\"$5}'",
        "command -v docker >/dev/null && docker info --format 'docker=ok' 2>/dev/null || echo 'docker=unavailable'",
        "command -v systemctl >/dev/null && echo systemd=$(systemctl is-system-running 2>/dev/null || true) || echo 'systemd=unavailable'",
        "command -v tailscale >/dev/null && tailscale status --json >/dev/null 2>&1 && echo 'tailscale=ok' || echo 'tailscale=unavailable'",
        "command -v cloudflared >/dev/null && echo 'cloudflared=installed' || echo 'cloudflared=unavailable'",
      ].join(" ; "), {
        timeoutMs: Math.min(60_000, env.MAX_JOB_DURATION_SECONDS * 1000),
        maxLogBytes: Math.min(env.MAX_LOG_BYTES, 16_384),
      });
      const output = `${result.stdout}\n${result.stderr}`;
      const disk = /disk_percent=(\d+)/.exec(output)?.[1];
      const ram = /ram_percent=(\d+)/.exec(output)?.[1];
      const status = result.exitCode === 0 ? "online" : "degraded";
      await admin.rest("health_checks", {
        method: "POST",
        body: {
          target_id: target.id,
          status,
          latency_ms: Date.now() - started,
          ram_percent: ram ? Number(ram) : null,
          disk_percent: disk ? Number(disk) : null,
          message: status === "online" ? "SSH health check passed." : "SSH health check returned warnings.",
          raw_summary: redact(output).slice(0, 4000),
          docker_status: /docker=ok/.test(output) ? "ok" : "unavailable",
          systemd_status: /systemd=([^\n]+)/.exec(output)?.[1]?.slice(0, 80) ?? "unknown",
          tailscale_status: /tailscale=ok/.test(output) ? "ok" : "unavailable",
          cloudflared_status: /cloudflared=installed/.test(output) ? "installed" : "unavailable",
        },
        prefer: "return=minimal",
      });
    } catch (error) {
      await admin.rest("health_checks", {
        method: "POST",
        body: {
          target_id: target.id,
          status: "offline",
          latency_ms: Date.now() - started,
          message: redact(error instanceof Error ? error.message : "Health check failed."),
          raw_summary: null,
        },
        prefer: "return=minimal",
      });
    }
  }
}

export async function startWorker(admin: AdminService, env: Environment): Promise<void> {
  if (!admin.enabled) throw new AppError(503, "admin_unavailable", "Supabase admin integration is required for the worker.");
  let active = 0;
  let healthRunning = false;
  const tick = async () => {
    await admin.rpc("mark_interrupted_executions", { p_stale_seconds: env.WORKER_STALE_SECONDS });
    while (active < env.MAX_CONCURRENT_JOBS) {
      const execution = await claimExecution(admin, env);
      if (!execution) break;
      active += 1;
      void runClaimedExecution(admin, env, execution).finally(() => { active -= 1; });
    }
  };
  const health = async () => {
    if (healthRunning) return;
    healthRunning = true;
    try {
      await runHealthChecks(admin, env);
    } finally {
      healthRunning = false;
    }
  };

  await tick();
  void health();
  setInterval(() => { void tick(); }, env.WORKER_POLL_INTERVAL_MS);
  setInterval(() => { void health(); }, env.HEALTH_CHECK_INTERVAL_MS);
}
