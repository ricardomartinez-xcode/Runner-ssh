export type ClaimableExecution = {
  status: string;
  confirmed_at?: string | null;
  locked_at?: string | null;
  heartbeat_at?: string | null;
  retry_count?: number | null;
  max_retries?: number | null;
};

export type ExecutionPatch = Record<string, string | number | boolean | null>;

function expired(timestamp: string | null | undefined, now: Date, seconds: number): boolean {
  if (!timestamp) return true;
  return Date.parse(timestamp) <= now.getTime() - seconds * 1000;
}

export function executionCanBeClaimed(execution: ClaimableExecution, now: Date, staleAfterSeconds: number): boolean {
  if (execution.status !== "queued") return false;
  if (!execution.confirmed_at) return false;
  const retries = execution.retry_count ?? 0;
  const maxRetries = execution.max_retries ?? 0;
  if (retries > maxRetries) return false;
  return expired(execution.heartbeat_at ?? execution.locked_at, now, staleAfterSeconds);
}

export function workerHeartbeatPatch(workerId: string, now: Date): ExecutionPatch {
  return {
    worker_id: workerId,
    heartbeat_at: now.toISOString(),
  };
}

export function nextRetryPatch(execution: Pick<ClaimableExecution, "retry_count" | "max_retries">, error: string, now: Date): ExecutionPatch {
  const retryCount = execution.retry_count ?? 0;
  const maxRetries = execution.max_retries ?? 0;
  const nextRetry = retryCount + 1;
  const common = {
    last_error: error,
    heartbeat_at: null,
    locked_at: null,
    worker_id: null,
  };

  if (nextRetry <= maxRetries) {
    return {
      ...common,
      status: "queued",
      retry_count: nextRetry,
    };
  }

  return {
    ...common,
    status: "failed",
    retry_count: retryCount,
    interrupted: true,
    finished_at: now.toISOString(),
  };
}
