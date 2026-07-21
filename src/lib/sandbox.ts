// VirusTotal + Hybrid Analysis sandbox API clients.
// Plain utility module (no "use server"). Used by server actions.

// ── Interfaces ────────────────────────────────────────────────────────────────

export interface VTFileReport {
  source: "virustotal";
  indicator: string;
  indicatorType: "hash";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  score: number;
  verdict: string | null;
  malwareFamily: string | null;
  tags: string[];
  fileType: string | null;
  fileSize: number | null;
  fileName: string | null;
  sha256: string | null;
  md5: string | null;
  sha1: string | null;
  ssdeep: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  techniques: string[];
  rawJson: string;
}

export interface VTIPReport {
  source: "virustotal";
  indicator: string;
  indicatorType: "ip";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  score: number;
  verdict: string | null;
  country: string | null;
  asOwner: string | null;
  asn: number | null;
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  techniques: string[];
  rawJson: string;
}

export interface VTDomainReport {
  source: "virustotal";
  indicator: string;
  indicatorType: "domain";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  score: number;
  verdict: string | null;
  registrar: string | null;
  creationDate: string | null;
  tags: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  techniques: string[];
  rawJson: string;
}

export interface HAReport {
  source: "hybrid-analysis";
  indicator: string;
  indicatorType: "hash";
  verdict: string | null;
  score: number;
  malwareFamily: string | null;
  tags: string[];
  fileType: string | null;
  fileSize: number | null;
  fileName: string | null;
  sha256: string | null;
  md5: string | null;
  sha1: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  techniques: string[];
  environmentDescription: string | null;
  rawJson: string;
}

export type SandboxReport =
  | VTFileReport
  | VTIPReport
  | VTDomainReport
  | HAReport;

// ── Input validation ─────────────────────────────────────────────────────────

const HASH_RE = /^[0-9a-fA-F]+$/;
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/;
const URL_RE = /^https?:\/\/.+/i;

/** Validate a hash string (SHA-256, SHA-1, or MD5). Returns true if valid. */
function isValidHash(hash: string): boolean {
  const trimmed = hash.trim();
  // Accept SHA-256 (64), SHA-1 (40), or MD5 (32) hex strings
  if (![64, 40, 32].includes(trimmed.length)) return false;
  return HASH_RE.test(trimmed);
}

/** Validate an IPv4 address string. Returns true if it looks like a valid IP. */
function isValidIP(ip: string): boolean {
  return IPV4_RE.test(ip.trim());
}

/** Validate a domain string. Returns true if it looks like a valid domain. */
function isValidDomain(domain: string): boolean {
  const trimmed = domain.trim();
  if (trimmed.length > 253) return false;
  return DOMAIN_RE.test(trimmed);
}

/** Validate a URL string. Returns true if it starts with http:// or https://. */
function isValidURL(url: string): boolean {
  return URL_RE.test(url.trim());
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Convert a Unix epoch (seconds) to an ISO-8601 date string, or null. */
function unixToISO(ts: number | null | undefined): string | null {
  if (typeof ts !== "number" || ts <= 0) return null;
  return new Date(ts * 1000).toISOString();
}

/**
 * Extract MITRE ATT&CK technique IDs (e.g. T1059, T1059.001) from an
 * arbitrary string via regex sweep. Deduplicates results.
 */
function extractMitreTechniques(raw: string): string[] {
  const matches = raw.match(/T\d{4}(?:\.\d{3})?/g);
  if (!matches) return [];
  return Array.from(new Set(matches));
}

/**
 * Detect the type of a threat indicator string.
 * Checks URL first (before domain, since URLs contain domain-like substrings),
 * then hash lengths (SHA-256 64, SHA-1 40, MD5 32), IPv4, domain.
 */
export function detectIndicatorType(
  value: string
): "hash" | "ip" | "domain" | "url" | "unknown" {
  const trimmed = value.trim();

  // URL — check before domain since URLs contain domain substrings
  if (/^https?:\/\//i.test(trimmed)) return "url";

  // SHA-256 (64 hex)
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return "hash";
  // SHA-1 (40 hex)
  if (/^[0-9a-fA-F]{40}$/.test(trimmed)) return "hash";
  // MD5 (32 hex)
  if (/^[0-9a-fA-F]{32}$/.test(trimmed)) return "hash";

  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(trimmed)) return "ip";

  // Domain — at least one dot, TLD of 2+ alpha chars, no whitespace
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(trimmed))
    return "domain";

  return "unknown";
}

// ── VirusTotal internals ──────────────────────────────────────────────────────

const VT_BASE = "https://www.virustotal.com/api/v3";

/**
 * Shared GET request to VirusTotal. Handles:
 *   404 → null
 *   429 → throw (rate limit)
 *   401/403 → throw (auth/config error)
 *   other non-ok → null (non-critical)
 *   network error → null
 */
async function vtFetch(path: string): Promise<any | null> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    throw new Error(
      "VIRUSTOTAL_API_KEY is not set. Add it to your environment variables."
    );
  }

  try {
    const res = await fetch(`${VT_BASE}${path}`, {
      method: "GET",
      headers: {
        "x-apikey": apiKey,
        Accept: "application/json",
      },
    });

    if (res.status === 404) return null;
    if (res.status === 429) {
      throw new Error(
        "VirusTotal rate limit exceeded (4 req/min on free tier)"
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `VirusTotal auth error (${res.status}). Check VIRUSTOTAL_API_KEY.`
      );
    }
    if (!res.ok) return null;

    return await res.json();
  } catch (err) {
    // Re-throw intentional errors (rate limit, auth, missing key)
    if (err instanceof Error && /rate limit|auth error|API_KEY/i.test(err.message)) {
      throw err;
    }
    // Network errors — non-critical
    return null;
  }
}

/**
 * Extract MITRE technique IDs from VT file attributes. Sweeps the full
 * stringified attributes so we catch techniques from sandbox_verdicts,
 * sigma_analysis_results, and popular_threat_classification alike.
 */
function extractVTTechniques(attrs: Record<string, any>): string[] {
  return extractMitreTechniques(JSON.stringify(attrs));
}

// ── VirusTotal: File/Hash lookup ──────────────────────────────────────────────

export async function vtLookupHash(
  hash: string
): Promise<VTFileReport | null> {
  if (!isValidHash(hash)) return null;

  const json = await vtFetch(`/files/${encodeURIComponent(hash.trim())}`);
  if (!json) return null;

  const attrs = json.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const classification = attrs.popular_threat_classification ?? {};
  const names: string[] = attrs.names ?? [];

  return {
    source: "virustotal",
    indicator: hash,
    indicatorType: "hash",
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    score: (stats.malicious ?? 0) + (stats.suspicious ?? 0),
    verdict: classification.suggested_threat_label ?? null,
    malwareFamily: classification.popular_threat_name?.[0]?.value ?? null,
    tags: attrs.tags ?? [],
    fileType: attrs.type_description ?? null,
    fileSize: typeof attrs.size === "number" ? attrs.size : null,
    fileName: attrs.meaningful_name ?? names[0] ?? null,
    sha256: attrs.sha256 ?? null,
    md5: attrs.md5 ?? null,
    sha1: attrs.sha1 ?? null,
    ssdeep: attrs.ssdeep ?? null,
    firstSeen: unixToISO(attrs.first_submission_date),
    lastSeen: unixToISO(attrs.last_analysis_date),
    techniques: extractVTTechniques(attrs),
    rawJson: JSON.stringify(attrs),
  };
}

// ── VirusTotal: IP lookup ─────────────────────────────────────────────────────

export async function vtLookupIP(ip: string): Promise<VTIPReport | null> {
  if (!isValidIP(ip)) return null;

  const json = await vtFetch(`/ip_addresses/${encodeURIComponent(ip.trim())}`);
  if (!json) return null;

  const attrs = json.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const rawJson = JSON.stringify(attrs);

  return {
    source: "virustotal",
    indicator: ip,
    indicatorType: "ip",
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    score: (stats.malicious ?? 0) + (stats.suspicious ?? 0),
    verdict: null,
    country: attrs.country ?? null,
    asOwner: attrs.as_owner ?? null,
    asn: typeof attrs.asn === "number" ? attrs.asn : null,
    tags: attrs.tags ?? [],
    firstSeen: unixToISO(attrs.first_submission_date),
    lastSeen: unixToISO(attrs.last_analysis_date),
    techniques: extractMitreTechniques(rawJson),
    rawJson,
  };
}

// ── VirusTotal: Domain lookup ─────────────────────────────────────────────────

export async function vtLookupDomain(
  domain: string
): Promise<VTDomainReport | null> {
  if (!isValidDomain(domain)) return null;

  const json = await vtFetch(`/domains/${encodeURIComponent(domain.trim())}`);
  if (!json) return null;

  const attrs = json.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const rawJson = JSON.stringify(attrs);

  return {
    source: "virustotal",
    indicator: domain,
    indicatorType: "domain",
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    score: (stats.malicious ?? 0) + (stats.suspicious ?? 0),
    verdict: null,
    registrar: attrs.registrar ?? null,
    creationDate: unixToISO(attrs.creation_date),
    tags: attrs.tags ?? [],
    firstSeen: unixToISO(attrs.first_submission_date),
    lastSeen: unixToISO(attrs.last_analysis_date),
    techniques: extractMitreTechniques(rawJson),
    rawJson,
  };
}

// ── Hybrid Analysis internals ─────────────────────────────────────────────────

const HA_BASE = "https://www.hybrid-analysis.com/api/v2";

/**
 * Shared POST request to Hybrid Analysis. Same error model as vtFetch.
 */
async function haFetch(
  path: string,
  body: URLSearchParams
): Promise<any | null> {
  const apiKey = process.env.HYBRID_ANALYSIS_API_KEY;
  if (!apiKey) {
    throw new Error(
      "HYBRID_ANALYSIS_API_KEY is not set. Add it to your environment variables."
    );
  }

  try {
    const res = await fetch(`${HA_BASE}${path}`, {
      method: "POST",
      headers: {
        "api-key": apiKey,
        "User-Agent": "Falcon Sandbox",
        Accept: "application/json",
      },
      body,
    });

    if (res.status === 404) return null;
    if (res.status === 429) {
      throw new Error("Hybrid Analysis rate limit exceeded (429).");
    }
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `Hybrid Analysis auth error (${res.status}). Check HYBRID_ANALYSIS_API_KEY.`
      );
    }
    if (!res.ok) return null;

    return await res.json();
  } catch (err) {
    if (err instanceof Error && /rate limit|auth error|API_KEY/i.test(err.message)) {
      throw err;
    }
    return null;
  }
}

// ── Hybrid Analysis: Hash lookup ──────────────────────────────────────────────

export async function haLookupHash(hash: string): Promise<HAReport | null> {
  if (!isValidHash(hash)) return null;

  const body = new URLSearchParams({ hash: hash.trim() });
  const json = await haFetch("/search/hash", body);

  if (!Array.isArray(json) || json.length === 0) return null;

  const item = json[0];
  const rawJson = JSON.stringify(item);

  // Extract MITRE technique IDs from mitre_attcks array
  const mitreAttacks: any[] = item.mitre_attcks ?? [];
  const techniques: string[] = [];
  for (const entry of mitreAttacks) {
    const id: string | undefined = entry.attck_id ?? entry.technique;
    if (id && /^T\d{4}/.test(id)) {
      techniques.push(id);
    }
  }
  // Also sweep the raw JSON for any technique IDs we may have missed
  const allTechniques = Array.from(
    new Set(techniques.concat(extractMitreTechniques(rawJson)))
  );

  // Tags: prefer classifications_tags, fall back to tags
  let tags: string[] = [];
  if (Array.isArray(item.classifications_tags) && item.classifications_tags.length > 0) {
    tags = item.classifications_tags;
  } else if (Array.isArray(item.tags)) {
    tags = item.tags;
  }

  const analysisTime: string | null = item.analysis_start_time ?? null;

  return {
    source: "hybrid-analysis",
    indicator: hash,
    indicatorType: "hash",
    verdict: item.verdict ?? null,
    score: typeof item.threat_score === "number" ? item.threat_score : 0,
    malwareFamily: item.vx_family ?? null,
    tags,
    fileType: item.type_short ?? null,
    fileSize: typeof item.size === "number" ? item.size : null,
    fileName: item.submit_name ?? null,
    sha256: item.sha256 ?? null,
    md5: item.md5 ?? null,
    sha1: item.sha1 ?? null,
    firstSeen: analysisTime,
    lastSeen: analysisTime,
    techniques: allTechniques,
    environmentDescription: item.environment_description ?? null,
    rawJson,
  };
}
