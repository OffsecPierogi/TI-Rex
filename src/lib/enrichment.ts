// AbuseIPDB + Shodan enrichment API clients.
// Plain utility module (no "use server"). Used by server actions.

export interface AbuseIPDBReport {
  source: "abuseipdb";
  indicator: string;
  indicatorType: "ip";
  abuseConfidenceScore: number;
  totalReports: number;
  countryCode: string | null;
  domain: string | null;
  isp: string | null;
  usageType: string | null;
  isWhitelisted: boolean;
  lastReportedAt: string | null;
  numDistinctUsers: number;
}

export interface ShodanReport {
  source: "shodan";
  indicator: string;
  indicatorType: "ip";
  org: string | null;
  isp: string | null;
  os: string | null;
  countryCode: string | null;
  city: string | null;
  ports: number[];
  vulns: string[];
  hostnames: string[];
  services: { port: number; transport: string; product: string | null; version: string | null }[];
  lastUpdate: string | null;
}

const ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2";
const SHODAN_BASE = "https://api.shodan.io";

const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

export async function abuseipdbLookup(ip: string): Promise<AbuseIPDBReport | null> {
  if (!IPV4_RE.test(ip.trim())) return null;

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) throw new Error("ABUSEIPDB_API_KEY is not set. Add it to your environment variables.");

  try {
    const url = `${ABUSEIPDB_BASE}/check?ipAddress=${encodeURIComponent(ip.trim())}&maxAgeInDays=90&verbose`;
    const res = await fetch(url, {
      headers: { Key: apiKey, Accept: "application/json" },
    });

    if (res.status === 429) throw new Error("AbuseIPDB rate limit exceeded.");
    if (res.status === 401 || res.status === 403) throw new Error(`AbuseIPDB auth error (${res.status}). Check ABUSEIPDB_API_KEY.`);
    if (!res.ok) return null;

    const json = await res.json();
    const d = json.data;
    if (!d) return null;

    return {
      source: "abuseipdb",
      indicator: ip.trim(),
      indicatorType: "ip",
      abuseConfidenceScore: d.abuseConfidenceScore ?? 0,
      totalReports: d.totalReports ?? 0,
      countryCode: d.countryCode ?? null,
      domain: d.domain ?? null,
      isp: d.isp ?? null,
      usageType: d.usageType ?? null,
      isWhitelisted: d.isWhitelisted ?? false,
      lastReportedAt: d.lastReportedAt ?? null,
      numDistinctUsers: d.numDistinctUsers ?? 0,
    };
  } catch (err) {
    if (err instanceof Error && /rate limit|auth error|API_KEY/i.test(err.message)) throw err;
    return null;
  }
}

export async function shodanLookup(ip: string): Promise<ShodanReport | null> {
  if (!IPV4_RE.test(ip.trim())) return null;

  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) throw new Error("SHODAN_API_KEY is not set. Add it to your environment variables.");

  try {
    const url = `${SHODAN_BASE}/shodan/host/${encodeURIComponent(ip.trim())}?key=${encodeURIComponent(apiKey)}`;
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
    });

    if (res.status === 404) return null;
    if (res.status === 429) throw new Error("Shodan rate limit exceeded.");
    if (res.status === 401 || res.status === 403) throw new Error(`Shodan auth error (${res.status}). Check SHODAN_API_KEY.`);
    if (!res.ok) return null;

    const d = await res.json();

    const services: ShodanReport["services"] = [];
    if (Array.isArray(d.data)) {
      for (const svc of d.data) {
        services.push({
          port: svc.port,
          transport: svc.transport ?? "tcp",
          product: svc.product ?? null,
          version: svc.version ?? null,
        });
      }
    }

    return {
      source: "shodan",
      indicator: ip.trim(),
      indicatorType: "ip",
      org: d.org ?? null,
      isp: d.isp ?? null,
      os: d.os ?? null,
      countryCode: d.country_code ?? null,
      city: d.city ?? null,
      ports: Array.isArray(d.ports) ? d.ports : [],
      vulns: Array.isArray(d.vulns) ? d.vulns : [],
      hostnames: Array.isArray(d.hostnames) ? d.hostnames : [],
      services,
      lastUpdate: d.last_update ?? null,
    };
  } catch (err) {
    if (err instanceof Error && /rate limit|auth error|API_KEY/i.test(err.message)) throw err;
    return null;
  }
}
