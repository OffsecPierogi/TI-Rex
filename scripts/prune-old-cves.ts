import "dotenv/config";
import { prisma } from "../src/lib/db";

const RETENTION_DAYS = 30;

async function main() {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400000);

  // Get IDs of CVEs linked to APTs — always keep these
  const aptLinked = await prisma.actorAdvisory.findMany({ select: { advisoryId: true } });
  const aptIds = new Set(aptLinked.map((a) => a.advisoryId));

  const candidates = await prisma.advisory.findMany({
    where: {
      type: "NVD",
      knownRansomware: false,
      publishedDate: { lt: cutoff },
    },
    select: { id: true },
  });

  const toDelete = candidates.filter((a) => !aptIds.has(a.id));

  if (toDelete.length === 0) {
    console.log("No old NVD CVEs to prune.");
    return;
  }

  const ids = toDelete.map((a) => a.id);
  for (let i = 0; i < ids.length; i += 1000) {
    await prisma.advisory.deleteMany({ where: { id: { in: ids.slice(i, i + 1000) } } });
  }

  console.log(`Pruned ${toDelete.length} NVD CVEs older than ${RETENTION_DAYS} days`);
}

main().catch(console.error).finally(() => process.exit(0));
