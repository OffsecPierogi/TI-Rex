import { prisma } from "../src/lib/db";

// ── AlienVault OTX Integration ──────────────────────────────────────────────
// Fetches subscribed pulses and APT-related search results from OTX,
// maps indicators to IOC records, and upserts them into the database.

const OTX_BASE = "https://otx.alienvault.com/api/v1";
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5_000;

// Map OTX indicator types to our IOC types
const TYPE_MAP: Record<string, string> = {
  IPv4: "ipv4",
  domain: "domain",
  hostname: "domain",
  URL: "url",
  "FileHash-SHA256": "sha256",
  "FileHash-MD5": "md5",
  "FileHash-SHA1": "sha1",
};

interface OtxIndicator {
  indicator: string;
  type: string;
  description: string;
  title: string;
  created: string;
}

interface OtxPulse {
  id: string;
  name: string;
  description: string;
  indicators: OtxIndicator[];
}

interface OtxPulseListResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: OtxPulse[];
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function truncate(s: string | undefined | null, max: number): string {
  if (!s) return "";
  return s.length > max ? s.slice(0, max) : s;
}

async function otxFetch(url: string, apiKey: string): Promise<Response> {
  let lastErr: Error | null = null;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    const resp = await fetch(url, {
      headers: { "X-OTX-API-KEY": apiKey },
    });

    if (resp.status === 429) {
      console.warn(`  Rate limited (429), waiting ${RETRY_DELAY_MS / 1000}s before retry ${attempt}/${MAX_RETRIES}...`);
      await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      lastErr = new Error(`HTTP 429 Too Many Requests`);
      continue;
    }

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText} for ${url}`);
    }

    return resp;
  }

  throw lastErr ?? new Error("Max retries exceeded");
}

// ── Fetch all pages of subscribed pulses ────────────────────────────────────

async function fetchSubscribedPulses(apiKey: string): Promise<OtxPulse[]> {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const modifiedSince = thirtyDaysAgo.toISOString().split("T")[0];

  let url: string | null =
    `${OTX_BASE}/pulses/subscribed?modified_since=${modifiedSince}&limit=50&page=1`;
  const allPulses: OtxPulse[] = [];

  while (url) {
    console.log(`  Fetching: ${url}`);
    const resp = await otxFetch(url, apiKey);
    const data: OtxPulseListResponse = await resp.json();
    allPulses.push(...data.results);
    url = data.next;
  }

  return allPulses;
}

// ── Fetch pulses from search endpoints ──────────────────────────────────────

// Hardcoded fallback queries used when the DB is unavailable
const FALLBACK_SEARCHES = [
  `${OTX_BASE}/pulses/subscribed?q=APT&limit=20`,
  `${OTX_BASE}/search/pulses?q=APT28&limit=10`,
  `${OTX_BASE}/search/pulses?q=APT29&limit=10`,
  `${OTX_BASE}/search/pulses?q=Lazarus&limit=10`,
  `${OTX_BASE}/search/pulses?q=${encodeURIComponent("Volt Typhoon")}&limit=10`,
];

const MAX_ACTOR_SEARCHES = 50;
const MIN_ACTOR_NAME_LENGTH = 4;

async function buildActorSearchUrls(): Promise<string[]> {
  // Query all active threat actors, prioritized by technique count (procedures)
  const actors = await prisma.threatActor.findMany({
    where: { deprecated: false, revoked: false },
    select: { name: true, _count: { select: { procedures: true } } },
    orderBy: { procedures: { _count: "desc" } },
  });

  const seen = new Set<string>();
  const urls: string[] = [];

  for (const actor of actors) {
    if (urls.length >= MAX_ACTOR_SEARCHES) break;

    const name = actor.name.trim();
    // Skip names that are too short to be meaningful search terms
    if (name.length < MIN_ACTOR_NAME_LENGTH) continue;

    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    urls.push(`${OTX_BASE}/search/pulses?q=${encodeURIComponent(name)}&limit=10`);
  }

  return urls;
}

async function fetchSearchPulses(apiKey: string): Promise<OtxPulse[]> {
  let searches: string[];

  try {
    const actorUrls = await buildActorSearchUrls();
    if (actorUrls.length === 0) {
      console.warn("  No threat actors found in DB, falling back to hardcoded searches");
      searches = FALLBACK_SEARCHES;
    } else {
      console.log(`  Built ${actorUrls.length} search queries from DB threat actors`);
      searches = actorUrls;
    }
  } catch (err) {
    console.warn(`  Warning: failed to query threat actors from DB (${err}), using hardcoded fallback`);
    searches = FALLBACK_SEARCHES;
  }

  const allPulses: OtxPulse[] = [];

  for (const url of searches) {
    try {
      console.log(`  Searching: ${url}`);
      const resp = await otxFetch(url, apiKey);
      const data = await resp.json();
      // /search/pulses returns { results: [...] }, /pulses/subscribed returns { results: [...] }
      const pulses: OtxPulse[] = data.results ?? [];
      allPulses.push(...pulses);
    } catch (err) {
      console.warn(`  Warning: search failed for ${url}: ${err}`);
      // Continue with remaining searches
    }
  }

  return allPulses;
}

// ── Process indicators from pulses into IOCs ────────────────────────────────

async function processIndicators(
  pulses: OtxPulse[]
): Promise<{ processed: number; created: number }> {
  let processed = 0;
  let created = 0;
  // In-memory dedup to avoid repeated DB lookups within a single run
  const seen = new Set<string>();

  for (const pulse of pulses) {
    if (!pulse.indicators || !Array.isArray(pulse.indicators)) continue;

    for (const ind of pulse.indicators) {
      const iocType = TYPE_MAP[ind.type];
      if (!iocType) continue; // Skip email and unknown types

      processed++;
      const dedupeKey = `${iocType}:${ind.indicator}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      // Check if it already exists in DB
      const existing = await prisma.iOC.findFirst({
        where: { type: iocType, value: ind.indicator },
      });

      if (existing) continue;

      const source = truncate(`OTX: ${pulse.name}`, 200);
      const description = truncate(
        ind.description || pulse.description,
        500
      );

      await prisma.iOC.create({
        data: {
          type: iocType,
          value: ind.indicator,
          source,
          description: description || undefined,
          firstSeen: ind.created ? new Date(ind.created) : undefined,
        },
      });
      created++;
    }
  }

  return { processed, created };
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey || apiKey.trim() === "") {
    console.log("OTX_API_KEY not set, skipping");
    process.exit(0);
  }

  const logEntry = await prisma.updateLog.create({
    data: { source: "otx", status: "running" },
  });

  try {
    console.log("=== AlienVault OTX Ingestion ===\n");

    // 1. Fetch subscribed pulses (paginated, last 30 days)
    console.log("Fetching subscribed pulses...");
    const subscribedPulses = await fetchSubscribedPulses(apiKey);
    console.log(`  Got ${subscribedPulses.length} subscribed pulses`);

    // 2. Fetch APT-related search results
    console.log("\nFetching APT-related searches...");
    const searchPulses = await fetchSearchPulses(apiKey);
    console.log(`  Got ${searchPulses.length} search result pulses`);

    // 3. Combine and process all pulses
    const allPulses = [...subscribedPulses, ...searchPulses];
    console.log(`\nProcessing ${allPulses.length} total pulses...`);
    const { processed, created } = await processIndicators(allPulses);

    console.log(`\n=== OTX Ingestion Complete ===`);
    console.log(`  Pulses processed: ${allPulses.length}`);
    console.log(`  Indicators examined: ${processed}`);
    console.log(`  IOCs created: ${created}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: processed,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("OTX ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "error",
        errorMessage: String(err),
        completedAt: new Date(),
      },
    });
    throw err;
  }
}

main().catch(console.error).finally(() => process.exit(0));
