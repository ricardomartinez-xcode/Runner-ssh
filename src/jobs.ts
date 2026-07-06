import { randomUUID } from "node:crypto";
import type { Environment } from "./config.js";
import type { Job, Principal } from "./types.js";
import { conflict, forbidden } from "./errors.js";
import type { Registry } from "./registry.js";
import type { FileStore } from "./store.js";
import type { Executors } from "./executors.js";
import { redact } from "./redaction.js";

export class Jobs {
  private readonly controllers = new Map<string, AbortController>();
  private active = 0;

  constructor(
    private readonly env: Environment,
    private readonly registry: Registry,
    private readonly store: FileStore,
    private readonly executors: Executors,
  ) {}

  async plan(principal: Principal, request: { target_id: string; collection_id: string; task_id: string }): Promise<Job> {
    const plan = this.registry.plan(principal, request.target_id, request.collection_id, request.task_id);
    const now = new Date();
    const expires = new Date(now.getTime() + this.env.JOB_CONFIRMATION_TTL_SECONDS * 1000);
    const job: Job = {
      id: randomUUID(),
      requester_subject: principal.subject,
      requester_roles: principal.roles,
      requester_scopes: principal.scopes,
      target_id: plan.targetId,
      collection_id: plan.collectionId,
      task_id: plan.taskId,
      status: "planned",
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
      command_preview: plan.commandPreview,
      output: "",
      output_truncated: false,
    };
    await this.store.create(job);
    return job;
  }

  async confirm(principal: Principal, jobId: string, confirmation: string): Promise<Job> {
    const job = await this.owned(principal, jobId);
    if (confirmation !== "EJECUTAR") throw conflict('Confirmation must be exactly "EJECUTAR".');
    if (job.status !== "planned") throw conflict(`Job cannot be confirmed from "${job.status}".`);
    if (Date.parse(job.expires_at) <= Date.now()) {
      return this.store.update(job.id, { status: "expired", completed_at: new Date().toISOString() });
    }
    const queued = await this.store.update(job.id, { status: "queued" });
    void this.run(queued);
    return queued;
  }

  async get(principal: Principal, jobId: string): Promise<Job> {
    return this.owned(principal, jobId);
  }

  async cancel(principal: Principal, jobId: string): Promise<Job> {
    const job = await this.owned(principal, jobId);
    if (["succeeded", "failed", "cancelled", "expired"].includes(job.status)) {
      throw conflict(`Job cannot be cancelled from "${job.status}".`);
    }
    this.controllers.get(job.id)?.abort();
    return this.store.update(job.id, {
      status: "cancelled",
      cancelled_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
    });
  }

  private async owned(principal: Principal, jobId: string): Promise<Job> {
    const job = await this.store.get(jobId);
    if (job.requester_subject !== principal.subject) throw forbidden("You may access only jobs you created.");
    return job;
  }

  private async run(job: Job): Promise<void> {
    if (this.active >= this.env.MAX_CONCURRENT_JOBS) {
      await this.store.update(job.id, {
        status: "failed",
        completed_at: new Date().toISOString(),
        error: "Runner concurrency limit reached. Plan the task again after active jobs complete.",
      });
      return;
    }

    this.active += 1;
    const controller = new AbortController();
    this.controllers.set(job.id, controller);
    try {
      const principal: Principal = {
        subject: job.requester_subject,
        roles: job.requester_roles,
        scopes: job.requester_scopes,
      };
      const plan = this.registry.plan(principal, job.target_id, job.collection_id, job.task_id);
      if (plan.commandPreview !== job.command_preview) {
        await this.store.update(job.id, {
          status: "failed",
          completed_at: new Date().toISOString(),
          error: "Runner configuration changed after planning. Plan the task again.",
        });
        return;
      }
      await this.store.update(job.id, { status: "running", started_at: new Date().toISOString() });
      const seconds = Math.min(plan.task.timeout_seconds ?? this.env.MAX_JOB_DURATION_SECONDS, this.env.MAX_JOB_DURATION_SECONDS);
      const result = await this.executors.execute(plan, controller.signal, seconds * 1000, this.env.MAX_LOG_BYTES);
      const current = await this.store.get(job.id);
      const patch = {
        output: redact(result.output),
        output_truncated: result.outputTruncated,
        exit_code: result.exitCode,
        completed_at: new Date().toISOString(),
      };
      if (current.status === "cancelled" || result.cancelled) {
        await this.store.update(job.id, { ...patch, status: "cancelled" });
      } else if (result.timedOut) {
        await this.store.update(job.id, { ...patch, status: "failed", error: "Task timed out." });
      } else if (result.exitCode === 0) {
        await this.store.update(job.id, { ...patch, status: "succeeded" });
      } else {
        await this.store.update(job.id, { ...patch, status: "failed", error: "Task exited with a non-zero code." });
      }
    } catch (error) {
      await this.store.update(job.id, {
        status: "failed",
        completed_at: new Date().toISOString(),
        error: redact(error instanceof Error ? error.message : "Unexpected runner error."),
      });
    } finally {
      this.controllers.delete(job.id);
      this.active -= 1;
    }
  }
}
