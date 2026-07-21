import { prisma } from "../src/lib/db";

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
}

interface KevFeed {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "cisa-kev", status: "running" },
  });

  try {
    console.log("Fetching CISA KEV feed...");
    const resp = await fetch(KEV_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const feed: KevFeed = await resp.json();
    console.log(`Got ${feed.vulnerabilities.length} vulnerabilities (catalog v${feed.catalogVersion})`);

    let created = 0;
    let updated = 0;

    for (const v of feed.vulnerabilities) {
      const advisoryId = v.cveID;
      const existing = await prisma.advisory.findUnique({ where: { advisoryId } });

      if (existing) {
        await prisma.advisory.update({
          where: { advisoryId },
          data: {
            title: v.vulnerabilityName,
            description: v.shortDescription,
            vendorProject: v.vendorProject,
            product: v.product,
            dateAdded: new Date(v.dateAdded),
            dueDate: new Date(v.dueDate),
            knownRansomware: v.knownRansomwareCampaignUse === "Known",
            rawJson: JSON.stringify(v),
          },
        });
        updated++;
      } else {
        await prisma.advisory.create({
          data: {
            advisoryId,
            title: v.vulnerabilityName,
            description: v.shortDescription,
            type: "kev",
            severity: "critical",
            cveId: v.cveID,
            vendorProject: v.vendorProject,
            product: v.product,
            dateAdded: new Date(v.dateAdded),
            dueDate: new Date(v.dueDate),
            knownRansomware: v.knownRansomwareCampaignUse === "Known",
            url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
            rawJson: JSON.stringify(v),
          },
        });
        created++;
      }
    }

    console.log(`\n=== CISA KEV Ingestion Complete ===`);
    console.log(`Created: ${created}, Updated: ${updated}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: feed.vulnerabilities.length,
        recordsCreated: created,
        recordsUpdated: updated,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("KEV ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
