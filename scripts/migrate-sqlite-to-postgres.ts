import Database from "better-sqlite3";
import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import { resolve } from "path";
import "dotenv/config";

const SQLITE_PATH = resolve(process.cwd(), "dev.db");
const BATCH_SIZE = 500;

const BOOL_FIELDS = new Set([
  "elevationRequired", "isSubtechnique", "deprecated", "revoked",
  "knownRansomware", "isManualOverride",
]);

const DATE_FIELDS = new Set([
  "createdAt", "updatedAt", "startedAt", "completedAt", "fetchedAt",
  "publishedAt", "firstSeen", "lastSeen", "dateAdded", "dueDate",
]);

function cleanRow(row: Record<string, unknown>): Record<string, unknown> {
  const cleaned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    if (value === null || value === undefined) {
      cleaned[key] = null;
    } else if (BOOL_FIELDS.has(key)) {
      cleaned[key] = value === 1 || value === true || value === "1" || value === "true";
    } else if (DATE_FIELDS.has(key)) {
      cleaned[key] = typeof value === "string" || typeof value === "number" ? new Date(value) : value;
    } else if (typeof value === "string") {
      cleaned[key] = value.replace(/\0/g, "");
    } else {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

async function main() {
  console.log(`Migrating from ${SQLITE_PATH} to Postgres...`);

  const sqlite = new Database(SQLITE_PATH, { readonly: true });
  const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
  const pg = new PrismaClient({ adapter });

  async function migrateTable(
    tableName: string,
    model: { createMany: (args: { data: Record<string, unknown>[]; skipDuplicates: boolean }) => Promise<unknown> },
  ) {
    const rows = sqlite.prepare(`SELECT * FROM "${tableName}"`).all() as Record<string, unknown>[];
    if (rows.length === 0) {
      console.log(`  ${tableName}: 0 rows (skipped)`);
      return;
    }

    for (let i = 0; i < rows.length; i += BATCH_SIZE) {
      const batch = rows.slice(i, i + BATCH_SIZE).map(cleanRow);
      await model.createMany({ data: batch, skipDuplicates: true });
    }

    console.log(`  ${tableName}: ${rows.length} rows migrated`);
  }

  try {
    console.log("\nMigrating tables...\n");

    await migrateTable("Tactic", pg.tactic as never);
    await migrateTable("Technique", pg.technique as never);
    await migrateTable("TacticTechnique", pg.tacticTechnique as never);
    await migrateTable("ThreatActor", pg.threatActor as never);
    await migrateTable("Campaign", pg.campaign as never);
    await migrateTable("Malware", pg.malware as never);
    await migrateTable("Tool", pg.tool as never);

    await migrateTable("Procedure", pg.procedure as never);
    await migrateTable("CampaignActor", pg.campaignActor as never);
    await migrateTable("MalwareTechnique", pg.malwareTechnique as never);
    await migrateTable("ToolTechnique", pg.toolTechnique as never);
    await migrateTable("ActorMalware", pg.actorMalware as never);
    await migrateTable("AtomicTest", pg.atomicTest as never);

    await migrateTable("Category", pg.category as never);
    await migrateTable("CategoryTechnique", pg.categoryTechnique as never);
    await migrateTable("CategoryActor", pg.categoryActor as never);

    await migrateTable("Advisory", pg.advisory as never);
    await migrateTable("IOC", pg.iOC as never);
    await migrateTable("DetectionRule", pg.detectionRule as never);
    await migrateTable("SandboxAnalysis", pg.sandboxAnalysis as never);
    await migrateTable("YaraRule", pg.yaraRule as never);
    await migrateTable("UpdateLog", pg.updateLog as never);

    await migrateTable("AppSetting", pg.appSetting as never);
    await migrateTable("FeedItem", pg.feedItem as never);
    await migrateTable("ActorFeedItem", pg.actorFeedItem as never);
    await migrateTable("OffensiveCommand", pg.offensiveCommand as never);

    console.log("\nMigration complete!");
  } finally {
    await pg.$disconnect();
    sqlite.close();
  }
}

main().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
