"use server";

import { prisma } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import { revalidatePath } from "next/cache";

/* ---------- Validation constants ---------- */

const IOC_MAX_BATCH_SIZE = 500;
const IOC_VALUE_MAX_LENGTH = 2048;
const IOC_SOURCE_MAX_LENGTH = 500;
const IOC_DESCRIPTION_MAX_LENGTH = 500;

const ALLOWED_IOC_TYPES = new Set([
  "ipv4", "ipv6", "sha256", "sha1", "md5",
  "domain", "url", "email", "ja3", "ja3s", "yara",
]);

const HASH_LENGTHS: Record<string, number> = {
  sha256: 64,
  md5: 32,
  sha1: 40,
};

const HEX_RE = /^[0-9a-fA-F]+$/;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
// Control characters U+0000-U+001F except \n (\x0A), \r (\x0D), \t (\x09)
const CONTROL_CHAR_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F]/;
// Stricter: no newlines/carriage-returns/tabs either (used for non-YARA values)
const ANY_CONTROL_CHAR_RE = /[\x00-\x1F]/;

/** Validate and sanitize a single IOC. Returns an error string or null if valid. */
function validateIOC(ioc: IOCInput): string | null {
  // Type whitelist
  if (!ALLOWED_IOC_TYPES.has(ioc.type)) {
    return `Unknown IOC type "${ioc.type}". Allowed types: ${[...ALLOWED_IOC_TYPES].join(", ")}`;
  }

  // Length limits
  if (ioc.value.length > IOC_VALUE_MAX_LENGTH) {
    return `IOC value exceeds ${IOC_VALUE_MAX_LENGTH} character limit`;
  }
  if (ioc.source.length > IOC_SOURCE_MAX_LENGTH) {
    return `IOC source exceeds ${IOC_SOURCE_MAX_LENGTH} character limit`;
  }
  if (ioc.description && ioc.description.length > IOC_DESCRIPTION_MAX_LENGTH) {
    return `IOC description exceeds ${IOC_DESCRIPTION_MAX_LENGTH} character limit`;
  }

  // Control character check (YARA values may contain newlines/tabs/carriage returns)
  if (ioc.type === "yara") {
    if (CONTROL_CHAR_RE.test(ioc.value)) {
      return "IOC value contains disallowed control characters";
    }
  } else {
    if (ANY_CONTROL_CHAR_RE.test(ioc.value)) {
      return "IOC value contains control characters";
    }
  }

  // Null byte check (already caught by control char check, but explicit)
  if (ioc.value.includes("\0")) {
    return "IOC value contains null bytes";
  }

  // IPv4 format validation
  if (ioc.type === "ipv4" && !IPV4_RE.test(ioc.value)) {
    return `Invalid IPv4 address format: "${ioc.value}"`;
  }

  // Hash length validation
  const expectedLength = HASH_LENGTHS[ioc.type];
  if (expectedLength !== undefined) {
    if (ioc.value.length !== expectedLength) {
      return `${ioc.type} hash must be exactly ${expectedLength} hex characters, got ${ioc.value.length}`;
    }
    if (!HEX_RE.test(ioc.value)) {
      return `${ioc.type} hash must contain only hexadecimal characters`;
    }
  }

  return null;
}

/* ---------- IOC Import ---------- */

interface IOCInput {
  type: string;
  value: string;
  source: string;
  description?: string;
}

export async function importIOCs(
  iocs: IOCInput[]
): Promise<{ ok: boolean; inserted: number; skipped: number; error?: string }> {
  try {
    await requireRole("EDITOR");
    if (!iocs.length) return { ok: false, inserted: 0, skipped: 0, error: "No IOCs provided" };

    // Max batch size check
    if (iocs.length > IOC_MAX_BATCH_SIZE) {
      return {
        ok: false,
        inserted: 0,
        skipped: 0,
        error: `Batch size ${iocs.length} exceeds maximum of ${IOC_MAX_BATCH_SIZE} IOCs per import`,
      };
    }

    // Sanitize: trim whitespace and strip null bytes from all values
    const sanitized = iocs.map((ioc) => ({
      ...ioc,
      value: ioc.value.trim().replace(/\0/g, ""),
      source: ioc.source.trim(),
      description: ioc.description?.trim(),
    }));

    // Validate each IOC
    for (let idx = 0; idx < sanitized.length; idx++) {
      const err = validateIOC(sanitized[idx]);
      if (err) {
        return { ok: false, inserted: 0, skipped: 0, error: `IOC #${idx + 1}: ${err}` };
      }
    }

    // Duplicate check: find existing type+value pairs
    const pairs = sanitized.map((i) => ({ type: i.type, value: i.value }));
    const existing = await prisma.iOC.findMany({
      where: {
        OR: pairs.map((p) => ({ type: p.type, value: p.value })),
      },
      select: { type: true, value: true },
    });
    const existingSet = new Set(existing.map((e) => `${e.type}|${e.value}`));

    const toInsert = sanitized.filter((i) => !existingSet.has(`${i.type}|${i.value}`));
    const skipped = sanitized.length - toInsert.length;

    if (toInsert.length > 0) {
      // Insert in batches to avoid query size limits
      const BATCH = 100;
      for (let i = 0; i < toInsert.length; i += BATCH) {
        const batch = toInsert.slice(i, i + BATCH);
        await Promise.all(
          batch.map((ioc) =>
            prisma.iOC.create({
              data: {
                type: ioc.type,
                value: ioc.value,
                source: ioc.source,
                description: ioc.description || null,
              },
            })
          )
        );
      }
    }

    revalidatePath("/iocs");
    return { ok: true, inserted: toInsert.length, skipped };
  } catch (err) {
    console.error("importIOCs error:", err);
    return { ok: false, inserted: 0, skipped: 0, error: String(err) };
  }
}

/* ---------- YARA Rule Import ---------- */

const YARA_NAME_MAX_LENGTH = 200;
const YARA_NAME_RE = /^[a-zA-Z0-9_-]+$/;
const YARA_CONTENT_MAX_BYTES = 100 * 1024; // 100KB
const ALLOWED_YARA_CATEGORIES = new Set([
  "ransomware", "rat", "stealer", "apt-tool", "packer", "webshell",
]);
const ALLOWED_SEVERITIES = new Set(["low", "medium", "high", "critical"]);

interface YaraRuleInput {
  name: string;
  content: string;
  category: string;
  severity: string;
  malwareId?: string;
  techniqueId?: string;
}

export async function importYaraRule(
  data: YaraRuleInput
): Promise<{ ok: boolean; id?: string; error?: string }> {
  try {
    await requireRole("EDITOR");
    const name = data.name.trim();
    const content = data.content.trim();

    if (!name) return { ok: false, error: "Rule name is required" };
    if (!content) return { ok: false, error: "Rule content is required" };

    // Name validation
    if (name.length > YARA_NAME_MAX_LENGTH) {
      return { ok: false, error: `Rule name exceeds ${YARA_NAME_MAX_LENGTH} character limit` };
    }
    if (!YARA_NAME_RE.test(name)) {
      return { ok: false, error: "Rule name must contain only alphanumeric characters, underscores, and hyphens" };
    }

    // Content length validation
    if (new TextEncoder().encode(data.content).length > YARA_CONTENT_MAX_BYTES) {
      return { ok: false, error: "Rule content exceeds 100KB limit" };
    }

    // Category whitelist (empty string is allowed -- maps to null)
    if (data.category && !ALLOWED_YARA_CATEGORIES.has(data.category)) {
      return {
        ok: false,
        error: `Unknown category "${data.category}". Allowed: ${[...ALLOWED_YARA_CATEGORIES].join(", ")}`,
      };
    }

    // Severity whitelist (empty string is allowed -- maps to null)
    if (data.severity && !ALLOWED_SEVERITIES.has(data.severity)) {
      return {
        ok: false,
        error: `Unknown severity "${data.severity}". Allowed: low, medium, high, critical`,
      };
    }

    const rule = await prisma.yaraRule.create({
      data: {
        name,
        rule: data.content,
        category: data.category || null,
        severity: data.severity || null,
        malwareId: data.malwareId || null,
        techniqueId: data.techniqueId || null,
      },
    });

    revalidatePath("/yara");
    return { ok: true, id: rule.id };
  } catch (err: unknown) {
    if (
      typeof err === "object" &&
      err !== null &&
      "code" in err &&
      (err as { code: string }).code === "P2002"
    ) {
      return { ok: false, error: "A YARA rule with this name already exists" };
    }
    console.error("importYaraRule error:", err);
    return { ok: false, error: String(err) };
  }
}

/* ---------- Detection Rule Import ---------- */

const DETECTION_NAME_MAX_LENGTH = 200;
const DETECTION_DESCRIPTION_MAX_LENGTH = 2000;
const DETECTION_QUERY_MAX_BYTES = 100 * 1024; // 100KB
const ALLOWED_DETECTION_FORMATS = new Set(["sigma", "kql", "splunk", "snort", "yara"]);
const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;

interface DetectionRuleInput {
  name: string;
  description: string;
  format: string;
  query: string;
  severity: string;
  category: string;
  techniqueExternalId?: string;
}

export async function importDetectionRule(
  data: DetectionRuleInput
): Promise<{ ok: boolean; id?: string; warning?: string; error?: string }> {
  try {
    await requireRole("EDITOR");
    const name = data.name.trim();
    const query = data.query.trim();

    if (!name) return { ok: false, error: "Rule name is required" };
    if (!query) return { ok: false, error: "Rule query is required" };

    // Name length validation
    if (name.length > DETECTION_NAME_MAX_LENGTH) {
      return { ok: false, error: `Rule name exceeds ${DETECTION_NAME_MAX_LENGTH} character limit` };
    }

    // Description length validation
    if (data.description && data.description.length > DETECTION_DESCRIPTION_MAX_LENGTH) {
      return { ok: false, error: `Description exceeds ${DETECTION_DESCRIPTION_MAX_LENGTH} character limit` };
    }

    // Query length validation
    if (new TextEncoder().encode(data.query).length > DETECTION_QUERY_MAX_BYTES) {
      return { ok: false, error: "Rule query exceeds 100KB limit" };
    }

    // Format whitelist
    if (!ALLOWED_DETECTION_FORMATS.has(data.format)) {
      return {
        ok: false,
        error: `Unknown format "${data.format}". Allowed: ${[...ALLOWED_DETECTION_FORMATS].join(", ")}`,
      };
    }

    // Severity whitelist (empty string is allowed -- maps to null)
    if (data.severity && !ALLOWED_SEVERITIES.has(data.severity)) {
      return {
        ok: false,
        error: `Unknown severity "${data.severity}". Allowed: low, medium, high, critical`,
      };
    }

    // Technique ID format validation
    const techId = data.techniqueExternalId?.trim().toUpperCase();
    if (techId && !TECHNIQUE_ID_RE.test(techId)) {
      return {
        ok: false,
        error: `Invalid technique ID format "${data.techniqueExternalId}". Expected format: T1234 or T1234.001`,
      };
    }

    let techniqueId: string | null = null;
    let warning: string | undefined;

    if (techId) {
      const technique = await prisma.technique.findUnique({
        where: { externalId: techId },
        select: { id: true },
      });
      if (technique) {
        techniqueId = technique.id;
      } else {
        warning = `Technique "${data.techniqueExternalId}" not found in database -- rule saved without technique link`;
      }
    }

    const rule = await prisma.detectionRule.create({
      data: {
        name,
        description: data.description || null,
        query: data.query,
        language: data.format,
        severity: data.severity || null,
        category: data.category || null,
        techniqueId,
      },
    });

    revalidatePath("/detections");
    return { ok: true, id: rule.id, warning };
  } catch (err) {
    console.error("importDetectionRule error:", err);
    return { ok: false, error: String(err) };
  }
}

/* ---------- Data fetchers for import form dropdowns ---------- */

export async function getDetectionCategories(): Promise<string[]> {
  const results = await prisma.detectionRule.findMany({
    where: { category: { not: null } },
    select: { category: true },
    distinct: ["category"],
    orderBy: { category: "asc" },
  });
  return results.map((r) => r.category).filter((c): c is string => c !== null);
}

/* ---------- Search input sanitization ---------- */

const SEARCH_QUERY_MAX_LENGTH = 100;
// Strip characters that could cause regex issues in downstream processing
const REGEX_SPECIAL_CHARS_RE = /[.*+?^${}()|[\]\\]/g;

function sanitizeSearchQuery(query: string): string | null {
  if (!query || query.length < 2) return null;
  const trimmed = query.slice(0, SEARCH_QUERY_MAX_LENGTH).trim();
  if (trimmed.length < 2) return null;
  return trimmed.replace(REGEX_SPECIAL_CHARS_RE, "");
}

export async function searchTechniques(query: string) {
  const sanitized = sanitizeSearchQuery(query);
  if (!sanitized) return [];

  return prisma.technique.findMany({
    where: {
      deprecated: false,
      revoked: false,
      OR: [
        { externalId: { contains: sanitized.toUpperCase() } },
        { name: { contains: sanitized } },
      ],
    },
    select: { id: true, externalId: true, name: true },
    orderBy: { externalId: "asc" },
    take: 20,
  });
}

export async function searchMalware(query: string) {
  const sanitized = sanitizeSearchQuery(query);
  if (!sanitized) return [];

  return prisma.malware.findMany({
    where: {
      OR: [
        { name: { contains: sanitized } },
        { aliases: { contains: sanitized } },
      ],
    },
    select: { id: true, name: true },
    orderBy: { name: "asc" },
    take: 20,
  });
}
