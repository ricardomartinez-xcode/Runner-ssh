import { isIP } from "node:net";

const usernamePattern = /^[A-Za-z_][A-Za-z0-9._-]{0,63}$/;
const dnsLabelPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export function isValidSshUsername(value: string): boolean {
  return usernamePattern.test(value);
}

export function isValidDnsHostname(value: string): boolean {
  if (!value || value.length > 253 || value.includes("..")) return false;
  return value.split(".").every((label) => dnsLabelPattern.test(label));
}

export function isValidSshHost(value: string, cloudflareTunnel = false): boolean {
  if (cloudflareTunnel) return isIP(value) === 0 && isValidDnsHostname(value);
  return isIP(value) !== 0 || isValidDnsHostname(value);
}
