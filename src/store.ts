import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Job } from "./types.js";
import { notFound } from "./errors.js";

type Database = { jobs: Record<string, Job> };

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export class FileStore {
  private readonly file: string;
  private data: Database = { jobs: {} };
  private writes: Promise<void> = Promise.resolve();

  constructor(directory: string) {
    this.file = join(directory, "jobs.json");
  }

  async init(): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    try {
      this.data = JSON.parse(await readFile(this.file, "utf8")) as Database;
      this.data.jobs ??= {};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await this.persist();
    }
  }

  async create(job: Job): Promise<void> {
    await this.serial(async () => {
      this.data.jobs[job.id] = clone(job);
      await this.persist();
    });
  }

  async get(id: string): Promise<Job> {
    const job = this.data.jobs[id];
    if (!job) throw notFound(`Job "${id}" was not found.`);
    return clone(job);
  }

  async update(id: string, patch: Partial<Job>): Promise<Job> {
    return this.serial(async () => {
      const current = this.data.jobs[id];
      if (!current) throw notFound(`Job "${id}" was not found.`);
      this.data.jobs[id] = { ...current, ...clone(patch) };
      await this.persist();
      return clone(this.data.jobs[id]);
    });
  }

  private async serial<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.writes;
    let release: (() => void) | undefined;
    this.writes = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }

  private async persist(): Promise<void> {
    const temp = `${this.file}.tmp`;
    await writeFile(temp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    await rename(temp, this.file);
  }
}
