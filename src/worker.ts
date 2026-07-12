import type { AdminService } from "./admin.js";
import type { Environment } from "./config.js";
import { AppError } from "./errors.js";
import { commandFromRow, runSshCommand, type CommandRow, type JsonRecord, type TargetRow } from "./execution-runner.js";
import { redact } from "./redaction.js";
import { nextRetryPatch, workerHeartbeatPatch, workerOwnershipFilter } from "./worker-state.js";

type ExecutionRow = JsonRecord & {
  id: string;
  target_id: string;
  command_id: string;
  retry_count?: number | null;
  max_retries?: number | null;
};

type ConnectionTestRow = JsonRecord & {
  id: string;
  target_id: string;
  enable_on_success?: boolean | null;
};

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function first<T>(value: unknown, label: string): T {
  if (!Array.isArray(value) || !isRecord(value[0])) throw new AppError(404, "not_found", `${label} not found.`);
  return value[0] as T;
}

async function audit(admin: AdminService, action: string, entityId: string, metadata: JsonRecord = {}, entityType = "execution"): Promise<void> {
  await admin.rest("audit_logs", {
    method: "POST",
    body: { action, entity_type: entityType, entity_id: entityId, metadata },
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

async function patchOwnedExecution(admin: AdminService, id: string, workerId: string, body: JsonRecord): Promise<boolean> {
  const rows = await admin.rest("executions", {
    method: "PATCH",
    query: workerOwnershipFilter(id, workerId),
    body,
    prefer: "return=representation",
  });
  return Array.isArray(rows) && rows.length === 1;
}

async function patchOwnedConnectionTest(admin: AdminService, id: string, workerId: string, body: JsonRecord): Promise<boolean> {
  const rows = await admin.rest("target_connection_tests", {
    method: "PATCH",
    query: `id=eq.${encodeURIComponent(id)}&status=eq.running&worker_id=eq.${encodeURIComponent(workerId)}`,
    body,
    prefer: "return=representation",
  });
  return Array.isArray(rows) && rows.length === 1;
}

function reportWorkerError(context: string, error: unknown): void {
  const message = redact(error instanceof Error ? error.message : String(error));
  process.stderr.write(`[worker] ${context}: ${message}\n`);
}

async function reportWorkerInstance(admin: AdminService, env: Environment, startedAt: string, activeJobs: number): Promise<void> {
  try {
    await admin.rest("worker_instances", {
      method: "POST",
      query: "on_conflict=worker_id",
      body: {
        worker_id: env.WORKER_ID,
        service: "relead-ops-worker",
        status: "online",
        started_at: startedAt,
        last_heartbeat: new Date().toISOString(),
        active_jobs: activeJobs,
        max_concurrent_jobs: env.MAX_CONCURRENT_JOBS,
        heartbeat_interval_ms: env.WORKER_HEARTBEAT_INTERVAL_MS,
        metadata: { node_version: process.version },
      },
      prefer: "resolution=merge-duplicates,return=minimal",
    });
  } catch (error) {
    const message = redact(error instanceof Error ? error.message : "Worker heartbeat update failed.");
    process.stderr.write(`[worker] heartbeat unavailable: ${message}\n`);
  }
}

export async function claimExecution(admin: AdminService, env: Environment): Promise<ExecutionRow | null> {
  const rows = await admin.rpc("claim_execution", {
    p_worker_id: env.WORKER_ID,
    p_lock_seconds: env.WORKER_LOCK_SECONDS,
  });
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return first<ExecutionRow>(rows, "Execution");
}

export async function claimConnectionTest(admin: AdminService, env: Environment): Promise<ConnectionTestRow | null> {
  const rows = await admin.rpc("claim_target_connection_test", { p_worker_id: env.WORKER_ID });
  if (!Array.isArray(rows) || rows.length === 0) return null;
  return first<ConnectionTestRow>(rows, "Connection test");
}

async function connectionTestTarget(admin: AdminService, targetId: string): Promise<TargetRow> {
  return first<TargetRow>(await admin.rest("targets", {
    query: `id=eq.${encodeURIComponent(targetId)}&select=id,name,type,host,port,username,auth_type,secret_ref,working_directory,known_hosts,enabled,environment&limit=1`,
  }), "Target");
}

export async function runClaimedConnectionTest(admin: AdminService, env: Environment, test: ConnectionTestRow): Promise<void> {
  const abortController = new AbortController();
  let heartbeat: NodeJS.Timeout | undefined;
  let heartbeatFailures = 0;
  let heartbeatInFlight = false;
  let leaseUncertain = false;

  const refreshLease = async () => {
    if (heartbeatInFlight || leaseUncertain) return;
    heartbeatInFlight = true;
    try {
      const owned = await patchOwnedConnectionTest(admin, test.id, env.WORKER_ID, workerHeartbeatPatch(env.WORKER_ID, new Date()));
      if (!owned) {
        leaseUncertain = true;
        abortController.abort();
      } else {
        heartbeatFailures = 0;
      }
    } catch (error) {
      heartbeatFailures += 1;
      reportWorkerError(`connection-test heartbeat failed for ${test.id}`, error);
      if (heartbeatFailures >= 3) {
        leaseUncertain = true;
        abortController.abort();
      }
    } finally {
      heartbeatInFlight = false;
    }
  };

  try {
    const target = await connectionTestTarget(admin, test.target_id);
    heartbeat = setInterval(() => { void refreshLease(); }, env.WORKER_HEARTBEAT_INTERVAL_MS);
    const result = await runSshCommand(admin, target, "whoami && hostname && uptime", {
      timeoutMs: Math.min(60_000, env.MAX_JOB_DURATION_SECONDS * 1000),
      maxLogBytes: Math.min(16_384, env.MAX_LOG_BYTES),
      signal: abortController.signal,
    });
    if (leaseUncertain) throw new AppError(409, "worker_lease_lost", "Worker lease could not be maintained.");
    const status = result.exitCode === 0 && !result.timedOut ? "succeeded" : "failed";
    const updated = await patchOwnedConnectionTest(admin, test.id, env.WORKER_ID, {
      status,
      worker_id: null,
      locked_at: null,
      heartbeat_at: null,
      stdout: result.stdout,
      stderr: result.stderr,
      stdout_truncated: result.stdoutTruncated,
      stderr_truncated: result.stderrTruncated,
      exit_code: result.exitCode,
      duration_ms: result.durationMs,
      error: status === "failed" ? result.timedOut ? "Connection test timed out." : "SSH connection test failed." : null,
      finished_at: new Date().toISOString(),
    });
    if (!updated) return;

    await admin.rest("targets", {
      method: "PATCH",
      query: `id=eq.${encodeURIComponent(test.target_id)}`,
      body: {
        last_tested_at: new Date().toISOString(),
        last_test_status: status === "succeeded" ? "passed" : "failed",
        last_test_message: status === "succeeded" ? "Worker SSH connection test passed." : "Worker SSH connection test failed.",
        ...(test.enable_on_success ? {
          enabled: status === "succeeded",
          disabled_reason: status === "succeeded" ? null : "Worker SSH connection test failed.",
        } : {}),
      },
      prefer: "return=minimal",
    });
    await audit(admin, `target.connection_test_${status}`, test.target_id, {
      connection_test_id: test.id,
      exit_code: result.exitCode,
      duration_ms: result.durationMs,
      worker_id: env.WORKER_ID,
      enable_on_success: Boolean(test.enable_on_success),
    }, "target");
  } catch (error) {
    const message = redact(error instanceof Error ? error.message : "Connection test failed.");
    try {
      const updated = await patchOwnedConnectionTest(admin, test.id, env.WORKER_ID, {
        status: "failed",
        worker_id: null,
        locked_at: null,
        heartbeat_at: null,
        error: message,
        finished_at: new Date().toISOString(),
      });
      if (updated) {
        await admin.rest("targets", {
          method: "PATCH",
          query: `id=eq.${encodeURIComponent(test.target_id)}`,
          body: {
            last_tested_at: new Date().toISOString(),
            last_test_status: "failed",
            last_test_message: message,
            ...(test.enable_on_success ? { enabled: false, disabled_reason: "Worker SSH connection test failed." } : {}),
          },
          prefer: "return=minimal",
        });
        await audit(admin, "target.connection_test_failed", test.target_id, { connection_test_id: test.id, error: message, worker_id: env.WORKER_ID }, "target");
      }
    } catch (patchError) {
      reportWorkerError(`could not persist connection test ${test.id}`, patchError);
    }
  } finally {
    if (heartbeat) clearInterval(heartbeat);
  }
}

export async function runClaimedExecution(admin: AdminService, env: Environment, execution: ExecutionRow): Promise<void> {
  let heartbeat: NodeJS.Timeout | undefined;
  const abortController = new AbortController();
  let heartbeatInFlight = false;
  let heartbeatFailures = 0;
  let leaseUncertain = false;

  const refreshLease = async () => {
    if (heartbeatInFlight || leaseUncertain) return;
    heartbeatInFlight = true;
    try {
      const owned = await patchOwnedExecution(admin, execution.id, env.WORKER_ID, workerHeartbeatPatch(env.WORKER_ID, new Date()));
      if (!owned) {
        leaseUncertain = true;
        abortController.abort();
      } else {
        heartbeatFailures = 0;
      }
    } catch (error) {
      heartbeatFailures += 1;
      reportWorkerError(`heartbeat failed for ${execution.id}`, error);
      if (heartbeatFailures >= 3) {
        leaseUncertain = true;
        abortController.abort();
      }
    } finally {
      heartbeatInFlight = false;
    }
  };

  try {
    await appendEvent(admin, execution.id, "system", `Worker ${env.WORKER_ID} started execution.\n`);
    heartbeat = setInterval(() => {
      void refreshLease();
    }, env.WORKER_HEARTBEAT_INTERVAL_MS);

    const { target, command } = await executionContext(admin, execution);
    const result = await runSshCommand(admin, target, commandFromRow(target, command), {
      timeoutMs: env.MAX_JOB_DURATION_SECONDS * 1000,
      maxLogBytes: env.MAX_LOG_BYTES,
      signal: abortController.signal,
      onStdout: (chunk, truncated) => appendEvent(admin, execution.id, "stdout", chunk, truncated),
      onStderr: (chunk, truncated) => appendEvent(admin, execution.id, "stderr", chunk, truncated),
    });
    if (leaseUncertain) throw new AppError(409, "worker_lease_lost", "Worker lease could not be maintained.");
    const status = result.exitCode === 0 && !result.timedOut ? "succeeded" : "failed";
    const updated = await patchOwnedExecution(admin, execution.id, env.WORKER_ID, {
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
    if (!updated) {
      await audit(admin, "execution.worker_ownership_lost", execution.id, { worker_id: env.WORKER_ID });
      return;
    }
    await appendEvent(admin, execution.id, "system", `Execution ${status} with exit code ${result.exitCode}.\n`);
    await audit(admin, `execution.${status}`, execution.id, { exit_code: result.exitCode, duration_ms: result.durationMs, worker_id: env.WORKER_ID });
  } catch (error) {
    const message = redact(error instanceof Error ? error.message : "Worker execution failed.");
    const patch = nextRetryPatch({
      retry_count: typeof execution.retry_count === "number" ? execution.retry_count : 0,
      max_retries: typeof execution.max_retries === "number" ? execution.max_retries : 2,
    }, message, new Date());
    try {
      const updated = await patchOwnedExecution(admin, execution.id, env.WORKER_ID, { ...patch, error: patch.status === "failed" ? message : null });
      if (updated) {
        await appendEvent(admin, execution.id, "system", `${message}\n`, false);
        await audit(admin, patch.status === "failed" ? "execution.failed" : "execution.retry_queued", execution.id, { error: message, worker_id: env.WORKER_ID });
      } else {
        reportWorkerError(`ownership lost for ${execution.id}`, error);
      }
    } catch (patchError) {
      reportWorkerError(`could not persist failure for ${execution.id}`, patchError);
    }
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
        "command -v vmstat >/dev/null && vmstat 1 2 | awk 'END {print \"cpu_percent=\" 100-$15}' || echo 'cpu_percent=unknown'",
        "free | awk '/Mem:/ {printf \"ram_percent=%d\\n\", ($3/$2)*100}'",
        "df -P / | awk 'NR==2 {gsub(\"%\",\"\",$5); print \"disk_percent=\"$5}'",
        "command -v docker >/dev/null && docker info --format 'docker=ok' 2>/dev/null || echo 'docker=unavailable'",
        "command -v systemctl >/dev/null && echo systemd=$(systemctl is-system-running 2>/dev/null || true) || echo 'systemd=unavailable'",
        "command -v cloudflared >/dev/null && echo 'cloudflared=installed' || echo 'cloudflared=unavailable'",
      ].join(" ; "), {
        timeoutMs: Math.min(60_000, env.MAX_JOB_DURATION_SECONDS * 1000),
        maxLogBytes: Math.min(env.MAX_LOG_BYTES, 16_384),
      });
      const output = `${result.stdout}\n${result.stderr}`;
      const disk = /disk_percent=(\d+)/.exec(output)?.[1];
      const ram = /ram_percent=(\d+)/.exec(output)?.[1];
      const cpu = /cpu_percent=(\d+)/.exec(output)?.[1];
      const diskPercent = disk ? Number(disk) : null;
      const ramPercent = ram ? Number(ram) : null;
      const cpuPercent = cpu ? Number(cpu) : null;
      const status = result.exitCode === 0 && ![diskPercent, ramPercent, cpuPercent].some((value) => value !== null && value >= 90) ? "online" : "degraded";
      await admin.rest("health_checks", {
        method: "POST",
        body: {
          target_id: target.id,
          status,
          latency_ms: Date.now() - started,
          cpu_percent: cpuPercent,
          ram_percent: ramPercent,
          disk_percent: diskPercent,
          message: status === "online" ? "SSH health check passed." : "SSH health check returned warnings.",
          raw_summary: redact(output).slice(0, 4000),
          docker_status: /docker=ok/.test(output) ? "ok" : "unavailable",
          systemd_status: /systemd=([^\n]+)/.exec(output)?.[1]?.slice(0, 80) ?? "unknown",
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
  const startedAt = new Date().toISOString();
  let active = 0;
  let healthRunning = false;
  let tickRunning = false;
  const tick = async () => {
    if (tickRunning) return;
    tickRunning = true;
    try {
      await admin.rpc("mark_interrupted_executions", { p_stale_seconds: env.WORKER_STALE_SECONDS });
      await admin.rpc("mark_interrupted_connection_tests", { p_stale_seconds: env.WORKER_STALE_SECONDS });
      while (active < env.MAX_CONCURRENT_JOBS) {
        const connectionTest = await claimConnectionTest(admin, env);
        if (connectionTest) {
          active += 1;
          void runClaimedConnectionTest(admin, env, connectionTest)
            .catch((error) => reportWorkerError(`connection test loop failed for ${connectionTest.id}`, error))
            .finally(() => { active -= 1; });
          continue;
        }
        const execution = await claimExecution(admin, env);
        if (!execution) break;
        active += 1;
        void runClaimedExecution(admin, env, execution)
          .catch((error) => reportWorkerError(`execution loop failed for ${execution.id}`, error))
          .finally(() => { active -= 1; });
      }
    } catch (error) {
      reportWorkerError("claim loop failed", error);
    } finally {
      tickRunning = false;
    }
  };
  const health = async () => {
    if (healthRunning) return;
    healthRunning = true;
    try {
      await runHealthChecks(admin, env);
    } catch (error) {
      reportWorkerError("health loop failed", error);
    } finally {
      healthRunning = false;
    }
  };

  await reportWorkerInstance(admin, env, startedAt, active);
  await tick();
  void health();
  setInterval(() => { void tick(); }, env.WORKER_POLL_INTERVAL_MS);
  setInterval(() => { void health(); }, env.HEALTH_CHECK_INTERVAL_MS);
  setInterval(() => {
    void reportWorkerInstance(admin, env, startedAt, active);
  }, env.WORKER_HEARTBEAT_INTERVAL_MS);
}
