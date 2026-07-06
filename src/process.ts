import { spawn } from "node:child_process";

export type ProcessResult = {
  exitCode: number | null;
  output: string;
  outputTruncated: boolean;
  timedOut: boolean;
  cancelled: boolean;
};

export function run(
  executable: string,
  args: string[],
  options: {
    env?: NodeJS.ProcessEnv;
    timeoutMs: number;
    maxOutputBytes: number;
    signal: AbortSignal;
  },
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { shell: false, env: options.env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let bytes = 0;
    let truncated = false;
    let timedOut = false;
    let cancelled = false;
    let done = false;

    const append = (prefix: string, data: Buffer) => {
      if (truncated) return;
      const raw = `${prefix}${data.toString("utf8")}`;
      const available = options.maxOutputBytes - bytes;
      if (available <= 0) { truncated = true; return; }
      const value = Buffer.from(raw).subarray(0, available).toString("utf8");
      output += value;
      bytes += Buffer.byteLength(value);
      if (Buffer.byteLength(value) < Buffer.byteLength(raw)) truncated = true;
    };
    const stop = (reason: "timeout" | "cancel") => {
      if (child.exitCode !== null || child.killed) return;
      if (reason === "timeout") timedOut = true; else cancelled = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 3000).unref();
    };
    const timer = setTimeout(() => stop("timeout"), options.timeoutMs);
    const abort = () => stop("cancel");
    options.signal.addEventListener("abort", abort, { once: true });
    child.stdout.on("data", (data: Buffer) => append("", data));
    child.stderr.on("data", (data: Buffer) => append("[stderr] ", data));
    child.on("error", (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      options.signal.removeEventListener("abort", abort);
      reject(error);
    });
    child.on("close", (exitCode) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      options.signal.removeEventListener("abort", abort);
      resolve({ exitCode, output, outputTruncated: truncated, timedOut, cancelled });
    });
  });
}
