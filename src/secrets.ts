import { spawn } from "node:child_process";
import type { SecretReference } from "./types.js";
import { AppError } from "./errors.js";

export interface SecretResolver {
  read(reference: SecretReference): Promise<string>;
}

function opRead(reference: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("op", ["read", reference], { shell: false, env: process.env, stdio: ["ignore", "pipe", "ignore"] });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => { output += chunk.toString("utf8"); });
    child.on("error", () => reject(new AppError(500, "secret_provider_unavailable", "1Password CLI is unavailable.")));
    child.on("close", (code) => {
      const secret = output.trim();
      if (code !== 0 || !secret) {
        reject(new AppError(500, "secret_resolution_failed", "Target credential resolution failed."));
        return;
      }
      resolve(secret);
    });
  });
}

export class Secrets implements SecretResolver {
  async read(reference: SecretReference): Promise<string> {
    if (reference.provider === "env") {
      const value = process.env[reference.reference];
      if (!value) throw new AppError(500, "secret_resolution_failed", "Configured environment secret is missing.");
      return value;
    }
    if (!process.env.OP_SERVICE_ACCOUNT_TOKEN) {
      throw new AppError(500, "secret_resolution_failed", "1Password service account is not configured.");
    }
    return opRead(reference.reference);
  }
}
