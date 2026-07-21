import "dotenv/config";
import { prisma } from "../src/lib/db";

const CVE_REGEX = /CVE-\d{4}-\d{4,}/gi;

async function main() {
  console.log("=== Actor-CVE Linking ===\n");

  const log = await prisma.updateLog.create({
    data: { source: "actor-cve-links", status: "running" },
  });

  try {
    // Get all procedures that have an actorId and a non-empty description
    const procedures = await prisma.procedure.findMany({
      where: { actorId: { not: null } },
      select: { actorId: true, description: true },
    });

    console.log(`Found ${procedures.length} actor procedures to scan`);

    // Build a map of cveId -> advisory.id for quick lookups
    const advisories = await prisma.advisory.findMany({
      where: { cveId: { not: null } },
      select: { id: true, cveId: true },
    });

    const cveToAdvisoryId = new Map<string, string>();
    for (const adv of advisories) {
      if (adv.cveId) {
        cveToAdvisoryId.set(adv.cveId.toUpperCase(), adv.id);
      }
    }
    console.log(`Loaded ${cveToAdvisoryId.size} advisories with CVE IDs`);

    // Scan all procedure descriptions for CVE IDs and collect unique actor-advisory pairs
    const pairs = new Set<string>();
    const toCreate: { actorId: string; advisoryId: string }[] = [];

    for (const proc of procedures) {
      if (!proc.actorId || !proc.description) continue;

      const matches = proc.description.match(CVE_REGEX);
      if (!matches) continue;

      for (const match of matches) {
        const cveId = match.toUpperCase();
        const advisoryId = cveToAdvisoryId.get(cveId);
        if (!advisoryId) continue;

        const key = `${proc.actorId}::${advisoryId}`;
        if (pairs.has(key)) continue;
        pairs.add(key);

        toCreate.push({ actorId: proc.actorId, advisoryId });
      }
    }

    console.log(`Found ${toCreate.length} unique actor-CVE pairs to link`);

    // Batch upsert all pairs
    let created = 0;
    for (const pair of toCreate) {
      try {
        await prisma.actorAdvisory.upsert({
          where: {
            actorId_advisoryId: {
              actorId: pair.actorId,
              advisoryId: pair.advisoryId,
            },
          },
          update: {},
          create: pair,
        });
        created++;
      } catch (err) {
        // Skip any constraint violations
        console.warn(`  Skipped pair: actor=${pair.actorId}, advisory=${pair.advisoryId}`, err);
      }
    }

    console.log(`\nCreated/verified ${created} actor-CVE links`);

    await prisma.updateLog.update({
      where: { id: log.id },
      data: {
        status: "success",
        recordsProcessed: procedures.length,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("Actor-CVE linking failed:", err);
    await prisma.updateLog.update({
      where: { id: log.id },
      data: {
        status: "error",
        errorMessage: err instanceof Error ? err.message : String(err),
        completedAt: new Date(),
      },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
