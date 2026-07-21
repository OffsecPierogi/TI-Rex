import "dotenv/config";
import { prisma } from "../src/lib/db";

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_API_KEY = process.env.NVD_API_KEY?.trim() || "";
const DELAY_MS = NVD_API_KEY ? 600 : 6000;
const RESULTS_PER_PAGE = 2000;
const INGEST_DAYS = 30;

interface NvdCvssData {
  baseScore: number;
  baseSeverity?: string;
  vectorString: string;
}

interface NvdMetric {
  cvssData: NvdCvssData;
}

interface NvdDescription {
  lang: string;
  value: string;
}

interface NvdWeakness {
  description: NvdDescription[];
}

interface NvdCpe {
  criteria: string;
  vulnerable: boolean;
}

interface NvdCpeNode {
  cpeMatch: NvdCpe[];
}

interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions?: NvdDescription[];
  metrics?: {
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: NvdMetric[];
  };
  weaknesses?: NvdWeakness[];
  configurations?: { nodes: NvdCpeNode[] }[];
}

interface NvdResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{ cve: NvdCve }>;
}

function extractCvss(metrics: NvdCve["metrics"]): { score: number; vector: string; severity: string } | null {
  if (!metrics) return null;
  const metric =
    metrics.cvssMetricV31?.[0] ??
    metrics.cvssMetricV30?.[0] ??
    metrics.cvssMetricV2?.[0];
  if (!metric?.cvssData) return null;
  const score = metric.cvssData.baseScore;
  let severity = metric.cvssData.baseSeverity?.toLowerCase() ?? "";
  if (!severity) {
    if (score >= 9.0) severity = "critical";
    else if (score >= 7.0) severity = "high";
    else if (score >= 4.0) severity = "medium";
    else severity = "low";
  }
  return { score, vector: metric.cvssData.vectorString, severity };
}

function extractDescription(cve: NvdCve): string {
  if (!cve.descriptions) return "No description available.";
  const en = cve.descriptions.find((d) => d.lang === "en");
  return en?.value ?? cve.descriptions[0]?.value ?? "No description available.";
}

function extractVendorProduct(cve: NvdCve): { vendor: string | null; product: string | null } {
  if (!cve.configurations) return { vendor: null, product: null };
  for (const config of cve.configurations) {
    for (const node of config.nodes) {
      for (const match of node.cpeMatch) {
        if (!match.vulnerable) continue;
        // CPE format: cpe:2.3:a:vendor:product:version:...
        const parts = match.criteria.split(":");
        if (parts.length >= 5) {
          return {
            vendor: parts[3] !== "*" ? parts[3] : null,
            product: parts[4] !== "*" ? parts[4] : null,
          };
        }
      }
    }
  }
  return { vendor: null, product: null };
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "nvd", status: "running" },
  });

  try {
    // Phase 1: Ingest recent CVEs from NVD (last N days)
    const pubStartDate = new Date(Date.now() - INGEST_DAYS * 86400000).toISOString();
    const pubEndDate = new Date().toISOString();

    const nvdHeaders: Record<string, string> = { "User-Agent": "TI-Rex/1.0 (threat-intel-dashboard)" };
    if (NVD_API_KEY) nvdHeaders["apiKey"] = NVD_API_KEY;

    console.log(`=== NVD CVE Ingestion (last ${INGEST_DAYS} days) ===`);
    console.log(`API key: ${NVD_API_KEY ? "configured (fast mode)" : "not set (rate limited — get one free at https://nvd.nist.gov/developers/request-an-api-key)"}`);
    console.log(`Date range: ${pubStartDate.slice(0, 10)} to ${pubEndDate.slice(0, 10)}\n`);

    let startIndex = 0;
    let totalResults = 0;
    let created = 0;
    let updated = 0;
    let processed = 0;
    let page = 0;

    do {
      page++;
      const params = new URLSearchParams({
        pubStartDate,
        pubEndDate,
        startIndex: String(startIndex),
        resultsPerPage: String(RESULTS_PER_PAGE),
      });

      const url = `${NVD_API_BASE}?${params}`;
      console.log(`Fetching page ${page} (startIndex=${startIndex})...`);

      const resp = await fetch(url, { headers: nvdHeaders });

      if (!resp.ok) {
        if (resp.status === 403 || resp.status === 429) {
          console.warn(`  Rate limited (${resp.status}), waiting 30s...`);
          await sleep(30000);
          continue;
        }
        throw new Error(`NVD API returned ${resp.status}: ${resp.statusText}`);
      }

      const data: NvdResponse = await resp.json();
      totalResults = data.totalResults;
      console.log(`  Got ${data.vulnerabilities.length} CVEs (${totalResults} total)`);

      for (const entry of data.vulnerabilities) {
        const cve = entry.cve;
        if (!cve.id || cve.vulnStatus === "Rejected") continue;

        const cvss = extractCvss(cve.metrics);
        const desc = extractDescription(cve);
        const { vendor, product } = extractVendorProduct(cve);
        const title = `${cve.id} — ${desc.slice(0, 200)}${desc.length > 200 ? "..." : ""}`;

        try {
          const existing = await prisma.advisory.findUnique({
            where: { advisoryId: cve.id },
            select: { id: true, lastModifiedDate: true },
          });

          if (existing) {
            // Update if NVD has newer data
            const nvdModified = new Date(cve.lastModified);
            if (!existing.lastModifiedDate || nvdModified > existing.lastModifiedDate) {
              await prisma.advisory.update({
                where: { id: existing.id },
                data: {
                  description: desc,
                  severity: cvss?.severity ?? null,
                  cvssScore: cvss?.score ?? null,
                  cvssVector: cvss?.vector ?? null,
                  vendorProject: vendor,
                  product,
                  publishedDate: new Date(cve.published),
                  lastModifiedDate: nvdModified,
                },
              });
              updated++;
            }
          } else {
            await prisma.advisory.create({
              data: {
                advisoryId: cve.id,
                cveId: cve.id,
                title,
                description: desc,
                type: "NVD",
                severity: cvss?.severity ?? null,
                cvssScore: cvss?.score ?? null,
                cvssVector: cvss?.vector ?? null,
                vendorProject: vendor,
                product,
                publishedDate: new Date(cve.published),
                lastModifiedDate: new Date(cve.lastModified),
                url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
              },
            });
            created++;
          }
          processed++;
        } catch (err) {
          // Skip duplicates silently
          if (err instanceof Error && err.message.includes("Unique constraint")) continue;
          console.warn(`  Error processing ${cve.id}: ${err}`);
        }
      }

      console.log(`  Progress: ${processed} processed, ${created} new, ${updated} updated`);

      startIndex += data.vulnerabilities.length;
      if (startIndex < totalResults) {
        await sleep(DELAY_MS);
      }
    } while (startIndex < totalResults);

    // Phase 2: Enrich existing advisories (from KEV etc.) missing CVSS
    console.log("\n=== Enriching existing advisories missing CVSS ===");
    const missing = await prisma.advisory.findMany({
      where: { cveId: { not: null }, cvssScore: null },
      select: { id: true, cveId: true },
      take: 200,
    });

    let enriched = 0;
    for (let i = 0; i < missing.length; i++) {
      const adv = missing[i];
      try {
        const resp = await fetch(`${NVD_API_BASE}?cveId=${adv.cveId}`, { headers: nvdHeaders });
        if (!resp.ok) {
          if (resp.status === 403 || resp.status === 429) {
            console.warn("  Rate limited, waiting 30s...");
            await sleep(30000);
          }
          continue;
        }
        const data: NvdResponse = await resp.json();
        if (!data.vulnerabilities?.length) continue;

        const nvdCve = data.vulnerabilities[0].cve;
        const cvss = extractCvss(nvdCve.metrics);
        if (cvss) {
          await prisma.advisory.update({
            where: { id: adv.id },
            data: {
              cvssScore: cvss.score,
              cvssVector: cvss.vector,
              severity: cvss.severity,
              publishedDate: new Date(nvdCve.published),
              lastModifiedDate: new Date(nvdCve.lastModified),
            },
          });
          enriched++;
        }
        if (i < missing.length - 1) await sleep(DELAY_MS);
      } catch {
        continue;
      }
    }
    console.log(`  Enriched ${enriched} of ${missing.length} advisories`);

    console.log(`\n=== NVD Ingestion Complete ===`);
    console.log(`New CVEs: ${created}, Updated: ${updated + enriched}, Total processed: ${processed}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: processed,
        recordsCreated: created,
        recordsUpdated: updated + enriched,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("NVD ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
