import { describe, expect, it } from "vitest";
import {
  executionCanBeClaimed,
  nextRetryPatch,
  workerHeartbeatPatch,
} from "../src/worker-state.js";

const now = new Date("2026-07-10T12:00:00.000Z");

describe("worker execution claim state", () => {
  it("claims only confirmed queued executions without a live lock", () => {
    expect(executionCanBeClaimed({
      status: "queued",
      confirmed_at: now.toISOString(),
      locked_at: null,
      heartbeat_at: null,
      retry_count: 0,
      max_retries: 2,
    }, now, 60)).toBe(true);

    expect(executionCanBeClaimed({
      status: "queued",
      confirmed_at: null,
      locked_at: null,
      heartbeat_at: null,
      retry_count: 0,
      max_retries: 2,
    }, now, 60)).toBe(false);

    expect(executionCanBeClaimed({
      status: "approval_required",
      confirmed_at: now.toISOString(),
      locked_at: null,
      heartbeat_at: null,
      retry_count: 0,
      max_retries: 2,
    }, now, 60)).toBe(false);
  });

  it("does not double-claim executions with a fresh worker heartbeat", () => {
    expect(executionCanBeClaimed({
      status: "queued",
      confirmed_at: now.toISOString(),
      locked_at: "2026-07-10T11:59:30.000Z",
      heartbeat_at: "2026-07-10T11:59:45.000Z",
      retry_count: 0,
      max_retries: 2,
    }, now, 60)).toBe(false);
  });

  it("marks retryable failures without exceeding max retries", () => {
    expect(nextRetryPatch({
      retry_count: 0,
      max_retries: 2,
    }, "Network timeout", now)).toMatchObject({
      status: "queued",
      retry_count: 1,
      last_error: "Network timeout",
    });

    expect(nextRetryPatch({
      retry_count: 2,
      max_retries: 2,
    }, "Network timeout", now)).toMatchObject({
      status: "failed",
      interrupted: true,
      last_error: "Network timeout",
    });
  });

  it("generates heartbeat patches with a stable worker id", () => {
    expect(workerHeartbeatPatch("worker-a", now)).toEqual({
      worker_id: "worker-a",
      heartbeat_at: now.toISOString(),
    });
  });
});
