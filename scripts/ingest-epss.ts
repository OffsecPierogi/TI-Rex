import "dotenv/config";
import { prisma } from "../src/lib/db";
import { gunzipSync } from "zlib";

const EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz";

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "epss", status: "running" },
  });

  try {
    console.log("Fetching EPSS scores from FIRST/Cyentia...");
    const resp = await fetch(EPSS_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);

    const compressed = Buffer.from(await resp.arrayBuffer());
    const csv = gunzipSync(compressed).toString("utf-8");

    // Parse CSV: skip comment lines (#...) and header row (cve,epss,percentile)
    const lines = csv.split("\n");
    const epssMap = new Map<string, { epss: number; percentile: number }>();

    for (const line of lines) {
      if (!line || line.startsWith("#")) continue;
      const [cve, epssStr, percentileStr] = line.split(",");
      if (!cve || cve === "cve") continue; // skip header
      const epss = parseFloat(epssStr);
      const percentile = parseFloat(percentileStr);
      if (!isNaN(epss) && !isNaN(percentile)) {
        epssMap.set(cve, { epss, percentile });
      }
    }

    console.log(`Parsed ${epssMap.size} EPSS scores`);

    // Fetch all advisories that have a cveId
    const advisories = await prisma.advisory.findMany({
      where: { cveId: { not: null } },
      select: { id: true, cveId: true },
    });

    console.log(`Found ${advisories.length} advisories with CVE IDs`);

    let updated = 0;
    const BATCH_SIZE = 500;

    // Process in batches using transactions
    for (let i = 0; i < advisories.length; i += BATCH_SIZE) {
      const batch = advisories.slice(i, i + BATCH_SIZE);
      const updates = [];

      for (const adv of batch) {
        const epssData = epssMap.get(adv.cveId!);
        if (epssData) {
          updates.push(
            prisma.advisory.update({
              where: { id: adv.id },
              data: {
                epssScore: epssData.epss,
                epssPercentile: epssData.percentile,
              },
            })
          );
        }
      }

      if (updates.length > 0) {
        await prisma.$transaction(updates);
        updated += updates.length;
      }

      if (i + BATCH_SIZE < advisories.length) {
        console.log(`  Processed ${Math.min(i + BATCH_SIZE, advisories.length)}/${advisories.length} advisories (${updated} matched)...`);
      }
    }

    console.log(`\n=== EPSS Ingestion Complete ===`);
    console.log(`Matched & updated: ${updated} of ${advisories.length} advisories`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: advisories.length,
        recordsUpdated: updated,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("EPSS ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
