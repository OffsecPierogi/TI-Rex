import { prisma } from "../src/lib/db";

// Abuse.ch ThreatFox — free, no auth required
// Provides IOCs (IPs, domains, URLs, hashes) tagged by malware family
// Uses the public export JSON endpoint (no API key needed)
// https://threatfox.abuse.ch/export/

const THREATFOX_EXPORT = "https://threatfox.abuse.ch/export/json/recent/";

const TYPE_MAP: Record<string, string> = {
  "ip:port": "ipv4",
  domain: "domain",
  url: "url",
  "md5_hash": "md5",
  "sha256_hash": "sha256",
  "sha1_hash": "sha1",
};

interface ThreatFoxIOC {
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  malware: string;
  malware_printable: string;
  confidence_level: number;
  first_seen_utc: string;
  reporter: string;
  tags: string[] | null;
}

function cleanIocValue(type: string, raw: string): string {
  if (type === "ipv4") {
    return raw.split(":")[0];
  }
  return raw;
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "threatfox", status: "running" },
  });

  try {
    console.log("=== ThreatFox IOC Ingestion ===\n");

    console.log("Fetching recent IOCs from ThreatFox export...");
    const resp = await fetch(THREATFOX_EXPORT, {
      headers: { "User-Agent": "ThreatIntelDashboard/1.0" },
      signal: AbortSignal.timeout(60_000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const rawData: Record<string, ThreatFoxIOC[]> = await resp.json();

    const allIocs: ThreatFoxIOC[] = [];
    for (const entries of Object.values(rawData)) {
      if (Array.isArray(entries)) allIocs.push(...entries);
    }

    if (allIocs.length === 0) {
      console.log("  No IOCs in export feed");
      await prisma.updateLog.update({
        where: { id: logEntry.id },
        data: { status: "success", recordsProcessed: 0, completedAt: new Date() },
      });
      return;
    }

    console.log(`  Got ${allIocs.length} IOCs from ThreatFox`);

    let created = 0;
    let skipped = 0;
    const seen = new Set<string>();

    for (const ioc of allIocs) {
      const iocType = TYPE_MAP[ioc.ioc_type];
      if (!iocType) continue;

      const value = cleanIocValue(iocType, ioc.ioc_value);
      if (!value) continue;

      const dedupeKey = `${iocType}:${value}`;
      if (seen.has(dedupeKey)) { skipped++; continue; }
      seen.add(dedupeKey);

      const existing = await prisma.iOC.findFirst({
        where: { type: iocType, value },
      });

      if (existing) { skipped++; continue; }

      const source = `ThreatFox ${ioc.malware_printable}`.slice(0, 200);
      const tagsStr = Array.isArray(ioc.tags) ? ioc.tags.join(", ") : (ioc.tags || "");
      const description = [
        ioc.malware_printable,
        ioc.threat_type,
        tagsStr || null,
        `confidence: ${ioc.confidence_level}%`,
      ].filter(Boolean).join(" — ").slice(0, 500);

      await prisma.iOC.create({
        data: {
          type: iocType,
          value,
          source,
          description,
          firstSeen: ioc.first_seen_utc ? new Date(ioc.first_seen_utc.replace(" ", "T") + "Z") : new Date(),
        },
      });
      created++;
    }

    console.log(`\n  Created: ${created}, Skipped: ${skipped}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: allIocs.length,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("ThreatFox ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
  }
}

main().catch(console.error).finally(() => process.exit(0));
