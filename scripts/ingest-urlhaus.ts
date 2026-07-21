import { prisma } from "../src/lib/db";

// Abuse.ch URLhaus — free, no auth required
// Tracks malicious URLs used for malware distribution
// Uses the public JSON download endpoint
// https://urlhaus.abuse.ch/downloads/

const URLHAUS_EXPORT = "https://urlhaus.abuse.ch/downloads/json_recent/";

interface UrlhausEntry {
  dateadded: string;
  url: string;
  url_status: string;
  last_online: string | null;
  threat: string;
  tags: string[] | null;
  urlhaus_link: string;
  reporter: string;
}

function defangUrl(url: string): string {
  return url
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/^http:\/\//i, "hxxp://");
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "urlhaus", status: "running" },
  });

  try {
    console.log("=== URLhaus Malicious URL Ingestion ===\n");

    console.log("Fetching recent malicious URLs...");
    const resp = await fetch(URLHAUS_EXPORT, {
      headers: { "User-Agent": "ThreatIntelDashboard/1.0" },
      signal: AbortSignal.timeout(60_000),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    const rawData: Record<string, UrlhausEntry[]> = await resp.json();

    const urls: UrlhausEntry[] = [];
    for (const entries of Object.values(rawData)) {
      if (Array.isArray(entries)) urls.push(...entries);
    }

    if (urls.length === 0) {
      console.log("  No URLs in export feed");
      await prisma.updateLog.update({
        where: { id: logEntry.id },
        data: { status: "success", recordsProcessed: 0, completedAt: new Date() },
      });
      return;
    }

    console.log(`  Got ${urls.length} URLs`);

    let createdUrls = 0;
    let createdDomains = 0;
    let skipped = 0;
    const seenDomains = new Set<string>();

    for (const entry of urls) {
      const defanged = defangUrl(entry.url);

      const existingUrl = await prisma.iOC.findFirst({
        where: { type: "url", value: defanged },
      });

      if (!existingUrl) {
        const tags = Array.isArray(entry.tags) ? entry.tags.join(", ") : "";
        const description = [
          entry.threat || "malware distribution",
          tags ? `tags: ${tags}` : null,
          `status: ${entry.url_status}`,
        ].filter(Boolean).join(" — ").slice(0, 500);

        await prisma.iOC.create({
          data: {
            type: "url",
            value: defanged,
            source: "URLhaus",
            description,
            firstSeen: entry.dateadded ? new Date(entry.dateadded.replace(" UTC", "Z").replace(" ", "T")) : new Date(),
          },
        });
        createdUrls++;
      } else {
        skipped++;
      }

      try {
        const host = new URL(entry.url).hostname;
        if (host && !seenDomains.has(host)) {
          seenDomains.add(host);
          const isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
          const hostType = isIP ? "ipv4" : "domain";

          const existingHost = await prisma.iOC.findFirst({
            where: { type: hostType, value: host },
          });

          if (!existingHost) {
            await prisma.iOC.create({
              data: {
                type: hostType,
                value: host,
                source: "URLhaus",
                description: `Malware distribution host (${entry.threat || "unknown"})`,
                firstSeen: entry.dateadded ? new Date(entry.dateadded.replace(" UTC", "Z").replace(" ", "T")) : new Date(),
              },
            });
            createdDomains++;
          }
        }
      } catch { /* invalid URL */ }
    }

    console.log(`\n  URLs created: ${createdUrls}`);
    console.log(`  Hosts created: ${createdDomains}`);
    console.log(`  Skipped: ${skipped}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: urls.length,
        recordsCreated: createdUrls + createdDomains,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("URLhaus ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
  }
}

main().catch(console.error).finally(() => process.exit(0));
