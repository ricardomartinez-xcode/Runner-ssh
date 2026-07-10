import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import type { AdminService } from "./admin.js";
import { AppError } from "./errors.js";

type SecretEnvelope = {
  v: 1;
  iv: string;
  tag: string;
  data: string;
};

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function encryptionKey(): Buffer {
  const raw = process.env.SSH_KEY_ENCRYPTION_SECRET?.trim();
  if (!raw || raw.length < 32) {
    throw new AppError(
      503,
      "managed_credentials_unavailable",
      "SSH_KEY_ENCRYPTION_SECRET must be configured in Render with at least 32 random characters.",
    );
  }
  return createHash("sha256").update(raw, "utf8").digest();
}

export function managedCredentialsEnabled(): boolean {
  return Boolean(process.env.SSH_KEY_ENCRYPTION_SECRET?.trim() && process.env.SSH_KEY_ENCRYPTION_SECRET.trim().length >= 32);
}

function encryptSecret(value: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const envelope: SecretEnvelope = {
    v: 1,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    data: encrypted.toString("base64url"),
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

function decryptSecret(value: string): string {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!isRecord(parsed) || parsed.v !== 1 || typeof parsed.iv !== "string" || typeof parsed.tag !== "string" || typeof parsed.data !== "string") {
      throw new Error("Invalid envelope");
    }
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(parsed.iv, "base64url"));
    decipher.setAuthTag(Buffer.from(parsed.tag, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(parsed.data, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    throw new AppError(500, "credential_decryption_failed", "The managed target credential could not be decrypted.");
  }
}

export async function storeManagedCredential(
  admin: AdminService,
  targetId: string,
  credential: string,
  actorId: string,
): Promise<string> {
  if (!credential.trim()) throw new AppError(400, "credential_required", "A password or private key is required.");
  const rows = await admin.rest("target_secrets", {
    method: "POST",
    query: "on_conflict=target_id",
    body: {
      target_id: targetId,
      ciphertext: encryptSecret(credential),
      created_by: actorId,
      updated_at: new Date().toISOString(),
    },
    prefer: "resolution=merge-duplicates,return=representation",
  });
  const row = Array.isArray(rows) && isRecord(rows[0]) ? rows[0] : undefined;
  if (!row || typeof row.id !== "string") throw new AppError(500, "credential_store_failed", "The managed credential could not be stored.");
  return `MANAGED:${row.id}`;
}

export async function readManagedCredential(admin: AdminService, reference: string): Promise<string> {
  const id = reference.slice("MANAGED:".length);
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new AppError(400, "invalid_secret_ref", "Invalid managed credential reference.");
  const rows = await admin.rest("target_secrets", {
    query: `id=eq.${encodeURIComponent(id)}&select=ciphertext&limit=1`,
  });
  const row = Array.isArray(rows) && isRecord(rows[0]) ? rows[0] : undefined;
  if (!row || typeof row.ciphertext !== "string") throw new AppError(404, "credential_not_found", "Managed target credential not found.");
  return decryptSecret(row.ciphertext);
}

export async function deleteManagedCredential(admin: AdminService, targetId: string): Promise<void> {
  await admin.rest("target_secrets", {
    method: "DELETE",
    query: `target_id=eq.${encodeURIComponent(targetId)}`,
    prefer: "return=minimal",
  });
}
