import { prisma } from "../src/lib/db";

const MALPEDIA_API = "https://malpedia.caad.fkie.fraunhofer.de/api";

// ISO 2-letter to full country name for common threat-intel nations
const ISO_TO_COUNTRY: Record<string, string> = {
  CN: "China",
  RU: "Russia",
  KP: "North Korea",
  IR: "Iran",
  US: "United States",
  GB: "United Kingdom",
  UK: "United Kingdom",
  FR: "France",
  DE: "Germany",
  IL: "Israel",
  IN: "India",
  PK: "Pakistan",
  VN: "Vietnam",
  TR: "Turkey",
  LB: "Lebanon",
  KR: "South Korea",
  JP: "Japan",
  UA: "Ukraine",
  BY: "Belarus",
  BR: "Brazil",
  NG: "Nigeria",
  SA: "Saudi Arabia",
  AE: "United Arab Emirates",
  EG: "Egypt",
  TW: "Taiwan",
  TH: "Thailand",
  MY: "Malaysia",
  SG: "Singapore",
  PH: "Philippines",
  ID: "Indonesia",
  MX: "Mexico",
  CO: "Colombia",
  AR: "Argentina",
  NL: "Netherlands",
  SE: "Sweden",
  PL: "Poland",
  RO: "Romania",
  CZ: "Czech Republic",
  ES: "Spain",
  IT: "Italy",
  AU: "Australia",
  NZ: "New Zealand",
  CA: "Canada",
  ZA: "South Africa",
  ET: "Ethiopia",
  KE: "Kenya",
};

interface MalpediaFamily {
  updated?: string;
  alt_names?: string[];
  common_name?: string;
  urls?: string[];
  description?: string;
  attribution?: string[];
}

interface MalpediaActorDetail {
  description?: string;
  meta?: {
    country?: string;
    refs?: string[];
    [key: string]: unknown;
  };
  families?: Record<string, unknown>;
}

/**
 * Parse aliases from a JSON string stored in the database.
 * Returns lowercased alias strings.
 */
function parseAliases(aliasJson: string | null): string[] {
  if (!aliasJson) return [];
  try {
    const parsed = JSON.parse(aliasJson);
    if (Array.isArray(parsed)) return parsed.map((a: string) => a.toLowerCase());
  } catch {
    // Not valid JSON — treat as comma-separated
    return aliasJson.split(",").map((a) => a.trim().toLowerCase()).filter(Boolean);
  }
  return [];
}

/**
 * Derive a human-readable name from a Malpedia family key.
 * Keys look like "win.cobalt_strike" — extract part after the dot,
 * replace underscores with spaces, and title-case.
 */
function familyKeyToName(key: string): string {
  const dotIdx = key.indexOf(".");
  const slug = dotIdx >= 0 ? key.slice(dotIdx + 1) : key;
  return slug.replace(/_/g, " ");
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchJson<T>(url: string, retries = 3): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const resp = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (resp.status === 429) {
      if (attempt < retries) {
        const wait = 30_000 * (attempt + 1);
        console.warn(`  Rate limited (429), waiting ${wait / 1000}s before retry...`);
        await sleep(wait);
        continue;
      }
      throw new Error(`HTTP 429 for ${url} after ${retries} retries`);
    }
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} for ${url}`);
    }
    return resp.json() as Promise<T>;
  }
  throw new Error(`Failed to fetch ${url}`);
}

async function main() {
  console.log("=== Malpedia Enrichment ===\n");

  const logEntry = await prisma.updateLog.create({
    data: { source: "malpedia", status: "running" },
  });

  let familiesMatched = 0;
  let descriptionsUpdated = 0;
  let actorsEnriched = 0;
  let totalFamilies = 0;
  let totalActors = 0;

  try {
    // ---------------------------------------------------------------
    // STEP 1: Fetch all Malpedia families and enrich malware records
    // ---------------------------------------------------------------
    console.log("Fetching Malpedia families...");
    const families = await fetchJson<Record<string, MalpediaFamily>>(
      `${MALPEDIA_API}/get/families`
    );
    totalFamilies = Object.keys(families).length;
    console.log(`  Retrieved ${totalFamilies} Malpedia families`);

    // Load all malware records into memory for efficient matching
    const allMalware = await prisma.malware.findMany({
      select: { id: true, name: true, aliases: true, description: true },
    });

    // Build lookup maps: lowercased name/alias -> malware record
    const malwareByName = new Map<string, typeof allMalware[0]>();
    for (const m of allMalware) {
      malwareByName.set(m.name.toLowerCase(), m);
      for (const alias of parseAliases(m.aliases)) {
        if (!malwareByName.has(alias)) {
          malwareByName.set(alias, m);
        }
      }
    }

    // Match Malpedia families to our malware
    for (const [key, family] of Object.entries(families)) {
      // Try matching by family key name (e.g., "win.cobalt_strike" -> "cobalt strike")
      const keyName = familyKeyToName(key).toLowerCase();

      let match = malwareByName.get(keyName);

      // Try common_name if present
      if (!match && family.common_name) {
        match = malwareByName.get(family.common_name.toLowerCase());
      }

      // Try alt_names
      if (!match && family.alt_names) {
        for (const altName of family.alt_names) {
          match = malwareByName.get(altName.toLowerCase());
          if (match) break;
        }
      }

      if (match) {
        familiesMatched++;

        // Update description only if ours is empty/null
        if (
          (!match.description || match.description.trim() === "") &&
          family.description &&
          family.description.trim() !== ""
        ) {
          await prisma.malware.update({
            where: { id: match.id },
            data: { description: family.description },
          });
          descriptionsUpdated++;
        }
      }
    }

    console.log(`  Matched ${familiesMatched}/${totalFamilies} families to existing malware`);
    console.log(`  Updated ${descriptionsUpdated} empty descriptions`);

    // ---------------------------------------------------------------
    // STEP 2: Fetch actor list and enrich threat actor records
    // ---------------------------------------------------------------
    console.log("\nFetching Malpedia actor list...");
    const actorNames = await fetchJson<string[]>(`${MALPEDIA_API}/list/actors`);
    totalActors = actorNames.length;
    console.log(`  Retrieved ${totalActors} Malpedia actors`);

    // Load all threat actors into memory
    const allActors = await prisma.threatActor.findMany({
      select: { id: true, name: true, aliases: true, country: true, description: true },
    });

    const actorByName = new Map<string, typeof allActors[0]>();
    for (const a of allActors) {
      actorByName.set(a.name.toLowerCase(), a);
      for (const alias of parseAliases(a.aliases)) {
        if (!actorByName.has(alias)) {
          actorByName.set(alias, a);
        }
      }
    }

    // Only fetch details for actors that match our database
    const actorsToProcess = actorNames.filter((n) => actorByName.has(n.toLowerCase()));
    console.log(`  ${actorsToProcess.length} of ${totalActors} match our database — fetching only those`);

    for (const actorName of actorsToProcess) {
      try {
        const encodedName = encodeURIComponent(actorName);
        const detail = await fetchJson<MalpediaActorDetail>(
          `${MALPEDIA_API}/get/actor/${encodedName}`
        );

        const match = actorByName.get(actorName.toLowerCase())!;
        const updates: Record<string, string> = {};

        if (!match.country && detail.meta?.country) {
          const isoCode = detail.meta.country.toUpperCase();
          const fullCountry = ISO_TO_COUNTRY[isoCode];
          if (fullCountry) {
            updates.country = fullCountry;
          }
        }

        if (
          (!match.description || match.description.trim() === "") &&
          detail.description &&
          detail.description.trim() !== ""
        ) {
          updates.description = detail.description;
        }

        if (Object.keys(updates).length > 0) {
          await prisma.threatActor.update({
            where: { id: match.id },
            data: updates,
          });
          actorsEnriched++;
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (!msg.includes("404")) {
          console.warn(`  Warning: Failed to fetch actor "${actorName}": ${msg}`);
        }
      }

      await sleep(1500);
    }

    console.log(`  Enriched ${actorsEnriched} threat actors`);

    // ---------------------------------------------------------------
    // STEP 3: Update log and final stats
    // ---------------------------------------------------------------
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: totalFamilies + actorsToProcess.length,
        recordsUpdated: descriptionsUpdated + actorsEnriched,
        completedAt: new Date(),
      },
    });

    console.log("\n=== Malpedia Enrichment Complete ===");
    console.log(`  Families fetched:       ${totalFamilies}`);
    console.log(`  Families matched:       ${familiesMatched}`);
    console.log(`  Descriptions updated:   ${descriptionsUpdated}`);
    console.log(`  Actors processed:       ${actorsToProcess.length} (of ${totalActors} in Malpedia)`);
    console.log(`  Actors enriched:        ${actorsEnriched}`);
  } catch (err) {
    console.error("Malpedia enrichment failed:", err);
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
