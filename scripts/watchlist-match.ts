import { prisma } from "../src/lib/db";
import { WATCHLIST_TO_DB_TYPES } from "../src/lib/ioc-validation";

/**
 * Watchlist Matching Script
 *
 * For each enabled watchlist, checks whether any watched IOC indicator
 * exists in the IOC database. Creates WatchlistAlert records for new
 * matches and optionally fires webhook notifications.
 */

interface WebhookPayload {
  watchlistName: string;
  iocType: string;
  iocValue: string;
  matchSource: string;
  matchDetail: string;
  alertCreatedAt: string;
}

async function sendWebhook(url: string, payload: WebhookPayload): Promise<void> {
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    });
    if (!resp.ok) {
      console.warn(`  Webhook returned ${resp.status} for ${url}`);
    }
  } catch (err) {
    console.warn(`  Webhook failed for ${url}:`, err instanceof Error ? err.message : err);
  }
}

async function main() {
  console.log("=== Watchlist IOC Matching ===\n");

  // Fetch all enabled watchlists with their items
  const watchlists = await prisma.watchlist.findMany({
    where: { enabled: true },
    include: {
      items: true,
    },
  });

  if (watchlists.length === 0) {
    console.log("No enabled watchlists found. Done.");
    return;
  }

  console.log(`Found ${watchlists.length} enabled watchlist(s)\n`);

  let totalNewAlerts = 0;

  for (const wl of watchlists) {
    if (wl.items.length === 0) continue;

    console.log(`Processing: ${wl.name} (${wl.items.length} items)`);

    for (const item of wl.items) {
      // Map watchlist type to database IOC types
      const dbTypes = WATCHLIST_TO_DB_TYPES[item.type];
      if (!dbTypes || dbTypes.length === 0) {
        // No DB type mapping (e.g. email, cve) — skip
        continue;
      }

      // Check for matching IOCs in the database (case-insensitive for PostgreSQL)
      const matchingIOCs = await prisma.iOC.findMany({
        where: {
          type: { in: dbTypes },
          value: { equals: item.value, mode: "insensitive" },
        },
        take: 100,
      });

      if (matchingIOCs.length === 0) continue;

      // Check which matches are already alerted
      const existingAlerts = await prisma.watchlistAlert.findMany({
        where: {
          watchlistId: wl.id,
          itemId: item.id,
          iocId: { in: matchingIOCs.map((m) => m.id) },
        },
        select: { iocId: true },
      });
      const alertedIocIds = new Set(existingAlerts.map((a) => a.iocId));

      // Create alerts for new matches
      for (const ioc of matchingIOCs) {
        if (alertedIocIds.has(ioc.id)) continue;

        const matchSource = ioc.source;
        const matchDetail = ioc.description
          ? `${ioc.type}:${ioc.value} — ${ioc.description}`
          : `${ioc.type}:${ioc.value}`;

        const alert = await prisma.watchlistAlert.create({
          data: {
            watchlistId: wl.id,
            itemId: item.id,
            iocId: ioc.id,
            matchSource,
            matchDetail,
            notifiedAt: wl.webhookUrl ? new Date() : null,
          },
        });

        totalNewAlerts++;
        console.log(`  MATCH: ${item.type}:${item.value} found in ${matchSource}`);

        // Send webhook if configured
        if (wl.webhookUrl) {
          await sendWebhook(wl.webhookUrl, {
            watchlistName: wl.name,
            iocType: item.type,
            iocValue: item.value,
            matchSource,
            matchDetail,
            alertCreatedAt: alert.createdAt.toISOString(),
          });
        }
      }
    }
  }

  console.log(`\nDone. Created ${totalNewAlerts} new alert(s).`);
}

main().catch(console.error);
