const patterns = [
  /-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+ PRIVATE KEY-----/g,
  /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{16,}\b/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9__]{20,}\b/g,
  /\bOP_SERVICE_ACCOUNT_TOKEN=[^\s]+/gi,
  /\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|PRIVATE_KEY|SERVICE_ROLE_KEY|API_KEY|CREDENTIAL)[A-Z0-9_]*\s*=\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/g,
  /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~-]+/gi,
  /\bBearer\s+[A-Za-z0-9._~-]{20,}\b/g,
];

const secretEnvironmentName = /(?:SECRET|TOKEN|PASSWORD|PASS|PRIVATE_KEY|SERVICE_ROLE|CREDENTIAL|API_KEY|KEY_ENCRYPTION)/i;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redact(text: string): string {
  let result = patterns.reduce((current, pattern) => current.replace(pattern, "[REDACTED]"), text);
  for (const [name, value] of Object.entries(process.env)) {
    if (!value || value.length < 8 || !secretEnvironmentName.test(name)) continue;
    result = result.replace(new RegExp(escapeRegExp(value), "g"), "[REDACTED]");
  }
  return result;
}
