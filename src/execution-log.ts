import { redact } from "./redaction.js";
import { TextDecoder } from "node:util";

export type ExecutionLogAppend = {
  value: string;
  truncated: boolean;
};

function truncateUtf8(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let end = Math.min(maxBytes, bytes.length); end >= Math.max(0, maxBytes - 3); end -= 1) {
    try {
      return decoder.decode(bytes.subarray(0, end));
    } catch {
      // A UTF-8 code point crosses the byte boundary; retry before it.
    }
  }
  return "";
}

export function appendExecutionLog(current: string | null | undefined, chunk: string, maxBytes: number): ExecutionLogAppend {
  const base = current ?? "";
  const safe = redact(chunk);
  const combined = `${base}${safe}`;
  const bytes = Buffer.byteLength(combined, "utf8");
  if (bytes <= maxBytes) return { value: combined, truncated: false };

  return { value: truncateUtf8(combined, maxBytes), truncated: true };
}
