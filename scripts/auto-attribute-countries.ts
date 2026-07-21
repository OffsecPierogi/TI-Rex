import { prisma } from "../src/lib/db";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

const COUNTRY_PATTERNS: [RegExp, string][] = [
  [/\bChina\b|\bChinese\b|\bPRC\b|\bPeople's Republic of China\b|\bBeijing\b/i, "China"],
  [/\bRussia\b|\bRussian\b|\bGRU\b|\bFSB\b|\bSVR\b|\bMoscow\b|\bKremlin\b/i, "Russia"],
  [/\bIran\b|\bIranian\b|\bIRGC\b|\bTehran\b|\bPersian\b/i, "Iran"],
  [/\bNorth Korea\b|\bDPRK\b|\bPyongyang\b/i, "North Korea"],
  [/\bSouth Korea\b|\bROK\b|\bSeoul\b(?!.*North)/i, "South Korea"],
  [/\bVietnam\b|\bVietnamese\b/i, "Vietnam"],
  [/\bIndia\b|\bIndian\b/i, "India"],
  [/\bPakistan\b|\bPakistani\b/i, "Pakistan"],
  [/\bTurkey\b|\bTurkish\b/i, "Turkey"],
  [/\bLebanon\b|\bLebanese\b|\bHezbollah\b/i, "Lebanon"],
  [/\bBelarus\b|\bBelarusian\b/i, "Belarus"],
  [/\bUAE\b|\bUnited Arab Emirates\b|\bEmirati\b/i, "UAE"],
  [/\bIsrael\b|\bIsraeli\b/i, "Israel"],
  [/\bBrazil\b|\bBrazilian\b/i, "Brazil"],
  [/\bPalestine\b|\bPalestinian\b|\bGaza\b|\bHamas\b/i, "Palestine"],
];

async function main() {
  const bundlePath = join(__dirname, "..", "data", "sources", "cti", "enterprise-attack", "enterprise-attack.json");
  if (!existsSync(bundlePath)) {
    console.log("MITRE CTI data not found, skipping auto-attribution");
    process.exit(0);
  }

  const bundle = JSON.parse(readFileSync(bundlePath, "utf-8"));
  const stixActors = bundle.objects.filter((o: { type: string; revoked?: boolean }) => o.type === "intrusion-set" && !o.revoked);

  const dbActors = await prisma.threatActor.findMany({
    where: { country: null, deprecated: false, revoked: false },
    select: { id: true, name: true, stixId: true },
  });

  const stixMap = new Map<string, string>();
  for (const s of stixActors) {
    stixMap.set(s.id, s.description ?? "");
  }

  let updated = 0;
  for (const actor of dbActors) {
    const desc = stixMap.get(actor.stixId) ?? "";
    if (!desc) continue;

    for (const [pattern, country] of COUNTRY_PATTERNS) {
      if (pattern.test(desc)) {
        await prisma.threatActor.update({
          where: { id: actor.id },
          data: { country },
        });
        console.log(`  ${actor.name} → ${country} (from STIX description)`);
        updated++;
        break;
      }
    }
  }

  console.log(`\nAuto-attributed ${updated} actors from MITRE STIX descriptions`);
  const remaining = await prisma.threatActor.count({ where: { country: null, deprecated: false, revoked: false } });
  console.log(`Remaining without country: ${remaining}`);
}

main().catch(console.error).finally(() => process.exit(0));
