import { redact } from "./redaction.js";

export type ExecutionLogAppend = {
  value: string;
  truncated: boolean;
};

export function appendExecutionLog(current: string | null | undefined, chunk: string, maxBytes: number): ExecutionLogAppend {
  const base = current ?? "";
  const safe = redact(chunk);
  const combined = `${base}${safe}`;
  const bytes = Buffer.byteLength(combined, "utf8");
  if (bytes <= maxBytes) return { value: combined, truncated: false };

  const buffer = Buffer.from(combined, "utf8").subarray(0, maxBytes);
  return { value: buffer.toString("utf8"), truncated: true };
}
