import "dotenv/config";
import { prisma } from "../src/lib/db";

async function main() {
  console.log("=== IOC Retention Pruning ===\n");

  const setting = await prisma.appSetting.findUnique({
    where: { key: "iocRetentionDays" },
  });
  const days = setting ? (parseInt(setting.value, 10) || 0) : 90;

  if (days === 0) {
    console.log("  Retention disabled (no limit) — skipping prune");
    await prisma.$disconnect();
    return;
  }

  const cutoff = new Date(Date.now() - days * 86_400_000);
  console.log(`  Retention window: ${days} days`);
  console.log(`  Cutoff date: ${cutoff.toISOString()}`);

  const totalBefore = await prisma.iOC.count();

  const staleIocs = await prisma.iOC.findMany({
    where: {
      createdAt: { lt: cutoff },
      advisoryId: null,
    },
    select: { id: true },
  });

  if (staleIocs.length === 0) {
    console.log(`  No stale IOCs found (${totalBefore.toLocaleString()} total)`);
    await prisma.$disconnect();
    return;
  }

  const ids = staleIocs.map((i) => i.id);

  const analysesDeleted = await prisma.sandboxAnalysis.deleteMany({
    where: { iocId: { in: ids } },
  });

  const result = await prisma.iOC.deleteMany({
    where: { id: { in: ids } },
  });

  const now = new Date().toISOString();
  await prisma.appSetting.upsert({
    where: { key: "iocLastPruned" },
    update: { value: now },
    create: { key: "iocLastPruned", value: now },
  });
  await prisma.appSetting.upsert({
    where: { key: "iocLastPrunedCount" },
    update: { value: String(result.count) },
    create: { key: "iocLastPrunedCount", value: String(result.count) },
  });

  await prisma.updateLog.create({
    data: {
      source: "ioc-prune",
      status: "success",
      recordsProcessed: totalBefore,
      recordsCreated: 0,
      recordsUpdated: result.count,
      completedAt: new Date(),
    },
  });

  const totalAfter = await prisma.iOC.count();
  console.log(`  Pruned ${result.count.toLocaleString()} stale IOCs (${analysesDeleted.count} linked analyses)`);
  console.log(`  Remaining: ${totalAfter.toLocaleString()} IOCs`);

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error("IOC pruning failed:", err);
  await prisma.$disconnect();
  process.exit(1);
});
