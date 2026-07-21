import "dotenv/config";
import { prisma } from "../src/lib/db";
import { readFileSync } from "fs";
import { join } from "path";

const GITHUB_ADVISORIES_API = "https://api.github.com/advisories";
const OSV_API = "https://api.osv.dev/v1";

const ECOSYSTEMS = ["npm", "pip", "go", "maven", "nuget", "rubygems", "crates.io"];

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description: string;
  severity: string;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    vulnerable_version_range: string | null;
  }>;
  html_url: string;
  published_at: string;
  withdrawn_at: string | null;
  type: string;
  identifiers: Array<{ type: string; value: string }>;
}

async function fetchGitHubAdvisories(params: Record<string, string>): Promise<GitHubAdvisory[]> {
  const url = new URL(GITHUB_ADVISORIES_API);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": "TI-Rex/1.0",
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `token ${process.env.GITHUB_TOKEN}`;
  }

  const resp = await fetch(url.toString(), { headers });

  if (!resp.ok) {
    if (resp.status === 429 || resp.status === 403) {
      console.warn(`  GitHub API rate limited (${resp.status}), skipping`);
      return [];
    }
    throw new Error(`GitHub API returned ${resp.status}`);
  }

  return resp.json();
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
  published?: string;
  withdrawn?: string;
  references?: Array<{ url: string }>;
}

async function checkOsvPackage(ecosystem: string, name: string): Promise<OsvVuln[]> {
  const resp = await fetch(`${OSV_API}/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: { ecosystem, name } }),
  });
  if (!resp.ok) return [];
  const data = await resp.json();
  return data.vulns ?? [];
}

function mapSeverity(sev: string | null | undefined): string | null {
  if (!sev) return null;
  const s = sev.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "moderate" || s === "medium") return "medium";
  if (s === "low") return "low";
  return null;
}

async function main() {
  console.log("=== Supply Chain Advisory Ingestion ===\n");

  const logEntry = await prisma.updateLog.create({
    data: { source: "supply-chain", status: "running" },
  });

  let created = 0;
  let skipped = 0;

  try {
    console.log("Phase 1: Fetching malicious package advisories...");
    const malwareAdvisories = await fetchGitHubAdvisories({
      type: "malware",
      per_page: "100",
    });
    console.log(`  Found ${malwareAdvisories.length} malware advisories`);

    for (const adv of malwareAdvisories) {
      for (const vuln of adv.vulnerabilities) {
        const eco = vuln.package.ecosystem.toLowerCase();
        try {
          await prisma.supplyChainAlert.upsert({
            where: {
              ecosystem_packageName_summary: {
                ecosystem: eco,
                packageName: vuln.package.name,
                summary: adv.summary.slice(0, 500),
              },
            },
            update: {},
            create: {
              ecosystem: eco,
              packageName: vuln.package.name,
              versions: vuln.vulnerable_version_range,
              severity: mapSeverity(adv.severity) ?? "critical",
              summary: adv.summary.slice(0, 500),
              details: adv.description?.slice(0, 5000) ?? null,
              aliases: JSON.stringify(adv.identifiers.map((i) => i.value)),
              url: adv.html_url,
              publishedAt: adv.published_at ? new Date(adv.published_at) : null,
              withdrawnAt: adv.withdrawn_at ? new Date(adv.withdrawn_at) : null,
            },
          });
          created++;
        } catch {
          skipped++;
        }
      }
    }

    await sleep(2000);

    console.log("\nPhase 2: Fetching critical ecosystem advisories...");
    for (const eco of ECOSYSTEMS) {
      try {
        const advisories = await fetchGitHubAdvisories({
          ecosystem: eco,
          severity: "critical",
          per_page: "50",
          sort: "published",
          direction: "desc",
        });
        console.log(`  ${eco}: ${advisories.length} critical advisories`);

        for (const adv of advisories) {
          for (const vuln of adv.vulnerabilities) {
            try {
              await prisma.supplyChainAlert.upsert({
                where: {
                  ecosystem_packageName_summary: {
                    ecosystem: vuln.package.ecosystem.toLowerCase(),
                    packageName: vuln.package.name,
                    summary: adv.summary.slice(0, 500),
                  },
                },
                update: {},
                create: {
                  ecosystem: vuln.package.ecosystem.toLowerCase(),
                  packageName: vuln.package.name,
                  versions: vuln.vulnerable_version_range,
                  severity: mapSeverity(adv.severity),
                  summary: adv.summary.slice(0, 500),
                  details: adv.description?.slice(0, 5000) ?? null,
                  aliases: JSON.stringify(adv.identifiers.map((i) => i.value)),
                  url: adv.html_url,
                  publishedAt: adv.published_at ? new Date(adv.published_at) : null,
                  withdrawnAt: adv.withdrawn_at ? new Date(adv.withdrawn_at) : null,
                },
              });
              created++;
            } catch {
              skipped++;
            }
          }
        }

        await sleep(2000);
      } catch (err) {
        console.warn(`  Failed to fetch ${eco} advisories:`, err);
      }
    }

    console.log("\nPhase 3: Checking TI-Rex dependencies against OSV...");
    try {
      const pkgJson = JSON.parse(
        readFileSync(join(__dirname, "..", "package.json"), "utf-8")
      );
      const deps = Object.keys({
        ...pkgJson.dependencies,
        ...pkgJson.devDependencies,
      });

      let checked = 0;
      let vulnFound = 0;
      for (const dep of deps) {
        const vulns = await checkOsvPackage("npm", dep);
        checked++;
        if (vulns.length > 0) {
          vulnFound += vulns.length;
          console.log(`  ⚠ ${dep}: ${vulns.length} known vulnerabilities`);
          for (const v of vulns) {
            const aliases = v.aliases ?? [];
            const affectedPkg = v.affected?.[0];
            const versionRange =
              affectedPkg?.ranges?.[0]?.events
                ?.map((e) =>
                  e.introduced ? `>=${e.introduced}` : e.fixed ? `<${e.fixed}` : ""
                )
                .filter(Boolean)
                .join(", ") ?? null;

            try {
              await prisma.supplyChainAlert.upsert({
                where: {
                  ecosystem_packageName_summary: {
                    ecosystem: "npm",
                    packageName: dep,
                    summary: (v.summary ?? v.id).slice(0, 500),
                  },
                },
                update: {},
                create: {
                  ecosystem: "npm",
                  packageName: dep,
                  versions: versionRange,
                  severity: mapSeverity(v.severity?.[0]?.score),
                  summary: (v.summary ?? v.id).slice(0, 500),
                  details: v.details?.slice(0, 5000) ?? null,
                  aliases: aliases.length > 0 ? JSON.stringify(aliases) : null,
                  url: v.references?.[0]?.url ?? null,
                  publishedAt: v.published ? new Date(v.published) : null,
                  withdrawnAt: v.withdrawn ? new Date(v.withdrawn) : null,
                },
              });
              created++;
            } catch {
              skipped++;
            }
          }
        }
        if (checked % 10 === 0) await sleep(500);
      }
      console.log(`  Checked ${checked} dependencies, found ${vulnFound} advisories`);
    } catch (err) {
      console.warn("  Failed to check own dependencies:", err);
    }

    console.log(`\n=== Supply Chain Ingestion Complete ===`);
    console.log(`Created: ${created}, Skipped/duplicate: ${skipped}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: created + skipped,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("Supply chain ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
