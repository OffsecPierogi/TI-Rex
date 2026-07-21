/**
 * IOC validation and normalization utilities for the watchlist feature.
 */

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE =
  /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:(:([0-9a-fA-F]{1,4})){1,7}$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}$/;
const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const HEX_RE = /^[0-9a-fA-F]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export const IOC_TYPES = [
  "ip",
  "domain",
  "hash-md5",
  "hash-sha1",
  "hash-sha256",
  "url",
  "email",
  "cve",
] as const;

export type IOCType = (typeof IOC_TYPES)[number];

interface ValidationResult {
  valid: boolean;
  normalized: string;
  error?: string;
}

function validateIP(value: string): ValidationResult {
  const trimmed = value.trim();
  if (IPV4_RE.test(trimmed)) {
    // Validate each octet is 0-255
    const octets = trimmed.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) {
      return { valid: true, normalized: trimmed };
    }
    return { valid: false, normalized: trimmed, error: "Invalid IPv4 — octets must be 0-255" };
  }
  if (IPV6_RE.test(trimmed)) {
    return { valid: true, normalized: trimmed.toLowerCase() };
  }
  return { valid: false, normalized: trimmed, error: "Invalid IP address format" };
}

function validateDomain(value: string): ValidationResult {
  const trimmed = value.trim().toLowerCase();
  if (!DOMAIN_RE.test(trimmed)) {
    return { valid: false, normalized: trimmed, error: "Invalid domain format" };
  }
  return { valid: true, normalized: trimmed };
}

function validateHash(value: string, expectedLength: number, label: string): ValidationResult {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length !== expectedLength) {
    return {
      valid: false,
      normalized: trimmed,
      error: `${label} must be exactly ${expectedLength} characters (got ${trimmed.length})`,
    };
  }
  if (!HEX_RE.test(trimmed)) {
    return { valid: false, normalized: trimmed, error: `${label} must contain only hex characters` };
  }
  return { valid: true, normalized: trimmed };
}

function validateURL(value: string): ValidationResult {
  const trimmed = value.trim();
  try {
    new URL(trimmed);
    return { valid: true, normalized: trimmed };
  } catch {
    // Also accept defanged URLs like hxxp://
    if (/^hxxps?:\/\//i.test(trimmed)) {
      return { valid: true, normalized: trimmed };
    }
    return { valid: false, normalized: trimmed, error: "Invalid URL format" };
  }
}

function validateEmail(value: string): ValidationResult {
  const trimmed = value.trim().toLowerCase();
  if (!EMAIL_RE.test(trimmed)) {
    return { valid: false, normalized: trimmed, error: "Invalid email format" };
  }
  return { valid: true, normalized: trimmed };
}

function validateCVE(value: string): ValidationResult {
  const trimmed = value.trim().toUpperCase();
  if (!CVE_RE.test(trimmed)) {
    return {
      valid: false,
      normalized: trimmed,
      error: "CVE must match format CVE-YYYY-NNNNN (e.g. CVE-2024-12345)",
    };
  }
  return { valid: true, normalized: trimmed };
}

export function validateIOC(type: string, value: string): ValidationResult {
  if (!value || !value.trim()) {
    return { valid: false, normalized: "", error: "Value cannot be empty" };
  }

  switch (type) {
    case "ip":
      return validateIP(value);
    case "domain":
      return validateDomain(value);
    case "hash-md5":
      return validateHash(value, 32, "MD5");
    case "hash-sha1":
      return validateHash(value, 40, "SHA-1");
    case "hash-sha256":
      return validateHash(value, 64, "SHA-256");
    case "url":
      return validateURL(value);
    case "email":
      return validateEmail(value);
    case "cve":
      return validateCVE(value);
    default:
      return { valid: false, normalized: value.trim(), error: `Unknown IOC type: ${type}` };
  }
}

/**
 * Map watchlist IOC types to database IOC types used in the IOC table.
 */
export const WATCHLIST_TO_DB_TYPES: Record<string, string[]> = {
  ip: ["ipv4", "ipv6"],
  domain: ["domain"],
  "hash-md5": ["md5"],
  "hash-sha1": ["sha1"],
  "hash-sha256": ["sha256"],
  url: ["url"],
  // email and cve have no IOC table equivalents currently
  email: [],
  cve: [],
};
