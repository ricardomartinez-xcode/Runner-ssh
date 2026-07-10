import { AppError } from "./errors.js";

export type TargetTypeOption = {
  value: "ssh" | "cloudflare_tunnel";
  label: string;
  help: string;
};

export type CredentialSource = "managed" | "environment" | "agent" | "reference";
export type TargetAuthType = "private_key" | "password" | "agent" | "token";

export type CredentialValidationInput = {
  authType: TargetAuthType;
  source: CredentialSource;
  credential?: string;
  credentialConfirmation?: string;
};

export type CredentialReferenceInput = {
  source: CredentialSource;
  environmentVariable?: string;
  secretReference?: string;
};

const privateKeyPattern = /-----BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE|ENCRYPTED PRIVATE) KEY-----[\s\S]+-----END (OPENSSH|RSA|EC|DSA|PRIVATE|ENCRYPTED PRIVATE) KEY-----/;

export function availableTargetTypes(): TargetTypeOption[] {
  return [
    {
      value: "ssh",
      label: "SSH normal",
      help: "Conecta por OpenSSH desde el worker de Render hacia un host alcanzable.",
    },
    {
      value: "cloudflare_tunnel",
      label: "SSH via Cloudflare Tunnel o bastion",
      help: "Usa SSH estricto hacia un host privado expuesto por túnel, bastion o relay ya operativo.",
    },
  ];
}

export function validateTargetCredential(input: CredentialValidationInput): void {
  if (input.source !== "managed") return;
  if (input.authType === "agent") return;
  const credential = input.credential?.trim() ?? "";
  if (!credential) throw new AppError(400, "credential_required", "Enter the password or private key.");
  if (input.authType === "password" && input.credentialConfirmation !== undefined && credential !== input.credentialConfirmation) {
    throw new AppError(400, "credential_confirmation_mismatch", "Password and confirmation must match.");
  }
  if (input.authType === "private_key" && !privateKeyPattern.test(credential)) {
    throw new AppError(400, "invalid_private_key", "The pasted value does not look like an OpenSSH or PEM private key.");
  }
}

export function normalizeCredentialReference(input: CredentialReferenceInput): string | null {
  if (input.source === "managed" || input.source === "agent") return null;
  if (input.source === "environment") {
    const normalized = input.environmentVariable?.trim() ?? "";
    if (!/^[A-Z_][A-Z0-9_]*$/.test(normalized)) {
      throw new AppError(400, "invalid_environment_variable", "Use only a valid Render variable name, for example RELEADSERVER_SSH_KEY.");
    }
    return `RENDER_ENV:${normalized}`;
  }

  const reference = input.secretReference?.trim() ?? "";
  if (!/^(ENV:|RENDER_ENV:|1PASSWORD:)/.test(reference)) {
    throw new AppError(400, "invalid_secret_ref", "The advanced reference must start with ENV:, RENDER_ENV:, or 1PASSWORD:.");
  }
  return reference;
}
