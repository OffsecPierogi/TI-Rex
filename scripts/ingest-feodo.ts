import { prisma } from "../src/lib/db";

// Abuse.ch Feodo Tracker — free, no auth required
// Tracks botnet C2 infrastructure (Dridex, Emotet, TrickBot, QakBot, etc.)
// https://feodotracker.abuse.ch/

const FEODO_RECENT = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt";
const FEODO_ONLINE_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";

interface FeodoEntry {
  ip_address: string;
  port: number;
  status: string;
  hostname: string | null;
  as_number: number;
  as_name: string;
  country: string;
  first_seen: string;
  last_online: string;
  malware: string;
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "feodo-tracker", status: "running" },
  });

  try {
    console.log("=== Feodo Tracker C2 Ingestion ===\n");

    console.log("Fetching online C2 servers...");
    const resp = await fetch(FEODO_ONLINE_JSON, {
      headers: { "User-Agent": "ThreatIntelDashboard/1.0" },
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const entries: FeodoEntry[] = await resp.json();
    console.log(`  Got ${entries.length} C2 entries`);

    let created = 0;
    let skipped = 0;

    for (const entry of entries) {
      const value = entry.ip_address;
      if (!value) continue;

      const existing = await prisma.iOC.findFirst({
        where: { type: "ipv4", value },
      });

      if (existing) { skipped++; continue; }

      const description = [
        `${entry.malware} botnet C2`,
        entry.port ? `port ${entry.port}` : null,
        entry.as_name ? `AS${entry.as_number} (${entry.as_name})` : null,
        entry.country ? `country: ${entry.country}` : null,
        `status: ${entry.status}`,
      ].filter(Boolean).join(" — ").slice(0, 500);

      await prisma.iOC.create({
        data: {
          type: "ipv4",
          value,
          source: `Feodo Tracker (${entry.malware})`,
          description,
          firstSeen: entry.first_seen ? new Date(entry.first_seen) : new Date(),
        },
      });
      created++;
    }

    console.log(`\n  Created: ${created}, Skipped (existing): ${skipped}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: entries.length,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("Feodo Tracker ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
  }
}

main().catch(console.error).finally(() => process.exit(0));
