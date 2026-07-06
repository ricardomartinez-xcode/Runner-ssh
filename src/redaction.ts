const patterns = [
  /-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9__]{20,}\b/g,
  /\bOP_SERVICE_ACCOUNT_TOKEN=[^\s]+/gi,
  /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~-]+/gi,
  /\bBearer\s+[A-Za-z0-9._~-]{20,}\b/g,
];

export function redact(text: string): string {
  return patterns.reduce((result, pattern) => result.replace(pattern, "[REDACTED]"), text);
}
