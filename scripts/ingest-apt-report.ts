import "dotenv/config";
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

import { prisma } from "../src/lib/db";

const REPO_API = "https://api.github.com/repos/blackorbird/apt_report/contents";
const README_URL =
  "https://raw.githubusercontent.com/blackorbird/apt_report/master/README.md";

const SKIP_DIRS = new Set([
  "tools", "ot", "osint", "summary", "data", "exploit_report",
  "information_operations", "cybercrime", "mobile-apt", "exploit",
  "web3 security", "aisecurity", "apt-hunting", "covid",
  "international strategic", "spyware", "cybermercenary", "anonymous",
  "ilobleed", "phpstudyghost", "simjacker", "0day _in the wild_.xlsx",
  "nsogroup", "intellexa", "cellebrite", "cytrox", "candiru",
  "magecart", "careto",
]);

const SKIP_FILES = new Set([
  "readme.md", ".gitkeep", ".ds_store", "license", "license.md",
]);

const ALIAS_MAP: Record<string, string[]> = {
  "group123": ["APT37", "ScarCruft", "Reaper", "Group123", "Ricochet Chollima"],
  "baby-kimsuky": ["Kimsuky", "Velvet Chollima"],
  "baby related kimsuky": ["Kimsuky", "Velvet Chollima"],
  "kimsuky": ["Kimsuky", "Velvet Chollima", "Thallium", "Black Banshee"],
  "oceanlotus": ["APT32", "OceanLotus", "Ocean Lotus"],
  "chafer-apt39": ["APT39", "Chafer", "Remix Kitten"],
  "transparenttribe": ["Transparent Tribe", "APT36", "Mythic Leopard"],
  "carbanak": ["Carbanak", "FIN7", "Anunak"],
  "lazarus": ["Lazarus Group", "Lazarus", "HIDDEN COBRA", "Labyrinth Chollima", "Diamond Sleet"],
  "konni": ["Konni", "KONNI"],
  "muddywater": ["MuddyWater", "Muddy Water", "MERCURY", "Mango Sandstorm"],
  "apt28": ["APT28", "Fancy Bear", "Sofacy", "Sednit", "Forest Blizzard", "Strontium"],
  "apt29": ["APT29", "Cozy Bear", "The Dukes", "Midnight Blizzard", "Nobelium"],
  "apt3": ["APT3", "Gothic Panda", "Pirpi", "Buckeye"],
  "apt34": ["APT34", "OilRig", "Helix Kitten", "Hazel Sandstorm"],
  "apt36": ["APT36", "Transparent Tribe", "Mythic Leopard"],
  "apt41": ["APT41", "Winnti Group", "Wicked Panda", "Brass Typhoon"],
  "apt43": ["APT43", "Kimsuky", "Emerald Sleet"],
  "turla": ["Turla", "Venomous Bear", "Waterbug", "Snake", "Secret Blizzard"],
  "winnti": ["Winnti Group", "Winnti", "APT41", "Wicked Panda"],
  "tick": ["TICK", "Bronze Butler", "Stalker Panda"],
  "sandworm": ["Sandworm Team", "Sandworm", "Voodoo Bear", "Seashell Blizzard", "IRIDIUM"],
  "darkhotel": ["DarkHotel", "Dark Hotel"],
  "gamaredon": ["Gamaredon Group", "Gamaredon", "Primitive Bear", "Aqua Blizzard", "Shuckworm"],
  "patchwork": ["Patchwork", "Dropping Elephant", "Monsoon"],
  "sidewinder": ["SideWinder", "Rattlesnake", "Razor Tiger"],
  "bitter": ["BITTER", "T-APT-17"],
  "donot": ["Donot Team", "APT-C-35"],
  "agrius": ["Agrius", "DEV-0227"],
  "wizard spider": ["Wizard Spider", "Gold Blackburn", "Grim Spider"],
  "charming kitten": ["Charming Kitten", "APT35", "Phosphorus", "Mint Sandstorm"],
  "ghostwriter": ["Ghostwriter", "UNC1151", "Storm-0257"],
  "machete": ["Machete", "El Machete"],
  "molerats": ["Molerats", "Gaza Cybergang", "Gaza Hackers Team"],
  "seaturtle": ["Sea Turtle"],
  "sidecopy": ["SideCopy"],
  "strongpity": ["StrongPity", "Promethium"],
  "sunburst": ["SUNBURST", "Nobelium", "APT29", "Midnight Blizzard"],
  "winter vivern": ["Winter Vivern", "UAC-0114"],
  "buhtrap": ["Buhtrap"],
  "calisto": ["Calisto", "COLDRIVER", "Star Blizzard"],
  "tortoiseshell": ["Tortoiseshell", "Imperial Kitten", "Crimson Sandstorm"],
  "londonblue": ["London Blue"],
  "dustsquad": ["DustSquad"],
  "whitecompany": ["White Company"],
  "blacktech": ["BlackTech", "Palmerworm", "Manga Taurus"],
  "blindeagle": ["Blind Eagle", "APT-C-36"],
  "badmagic": ["Bad Magic", "Red Stinger"],
  "deadlykiss": ["DeadlyKiss"],
  "metador": ["Metador"],
  "arid viper": ["Arid Viper", "Desert Falcon", "APT-C-23"],
  "zoopark": ["ZooPark"],
  "confucius": ["Confucius", "Confucius APT"],
  "equationgroup": ["Equation Group", "Equation"],
  "lamberts": ["Lamberts", "Longhorn"],
  "nazar": ["Nazar"],
  "fin6": ["FIN6"],
  "fin7": ["FIN7", "Carbanak"],
  "jaku": ["Lazarus Group"],
};

interface ReportEntry {
  group: string;
  title: string;
  url: string;
  date: string | null;
}

interface GhFile {
  name: string;
  type: string;
  html_url: string;
  download_url: string | null;
  size: number;
}

function parseReadme(text: string): ReportEntry[] {
  const entries: ReportEntry[] = [];
  const sections = text.split(/^###\s+/m);

  for (const section of sections) {
    if (!section.trim()) continue;
    const lines = section.split("\n");
    const groupLine = lines[0].trim();
    if (!groupLine) continue;

    let currentTitle = "";
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith("▶") || line.startsWith(">")) {
        currentTitle = line.replace(/^[▶>]\s*/, "").trim();
      }
      const urlMatch = line.match(/(https?:\/\/\S+)/);
      if (urlMatch) {
        const url = urlMatch[1].replace(/[).,;]+$/, "");
        const dateMatch = line.match(/\(([^)]*\d{4}[^)]*)\)/);
        entries.push({
          group: groupLine,
          title: currentTitle || groupLine,
          url,
          date: dateMatch ? dateMatch[1].trim() : null,
        });
        currentTitle = "";
      }
    }
  }
  return entries;
}

function titleFromFilename(name: string): string {
  return name
    .replace(/\.(pdf|docx?|xlsx?|pptx?|txt|md|csv|html|zip)$/i, "")
    .replace(/[_-]+/g, " ")
    .trim();
}

async function fetchGithubDir(path: string): Promise<GhFile[]> {
  const url = `${REPO_API}/${encodeURIComponent(path)}`;
  const resp = await fetch(url, {
    headers: { "Accept": "application/vnd.github.v3+json" },
  });
  if (!resp.ok) {
    if (resp.status === 403) {
      console.log(`  [rate-limited] Pausing 60s...`);
      await new Promise(r => setTimeout(r, 60000));
      const retry = await fetch(url, {
        headers: { "Accept": "application/vnd.github.v3+json" },
      });
      if (!retry.ok) return [];
      return retry.json() as Promise<GhFile[]>;
    }
    return [];
  }
  return resp.json() as Promise<GhFile[]>;
}

async function fetchTopLevelDirs(): Promise<string[]> {
  const resp = await fetch(REPO_API, {
    headers: { "Accept": "application/vnd.github.v3+json" },
  });
  if (!resp.ok) {
    console.error(`[!] Failed to list repo root: ${resp.status}`);
    return [];
  }
  const items = await resp.json() as GhFile[];
  return items
    .filter(i => i.type === "dir")
    .map(i => i.name)
    .filter(n => !SKIP_DIRS.has(n.toLowerCase()));
}

function normalizeForMatch(s: string): string {
  return s.toLowerCase().replace(/[-_\s.]+/g, "").replace(/^apt/, "apt");
}

function tryParseDate(s: string): Date | null {
  try {
    const cleaned = s.replace(/,/g, "").replace(/\s+/g, " ").trim();
    const d = new Date(cleaned);
    if (!isNaN(d.getTime())) return d;
    const parts = s.match(/(\w+)\s+(\d{1,2})\s*,?\s*(\d{4})/);
    if (parts) {
      const d2 = new Date(`${parts[1]} ${parts[2]}, ${parts[3]}`);
      if (!isNaN(d2.getTime())) return d2;
    }
    return null;
  } catch {
    return null;
  }
}

async function main() {
  console.log("[*] Loading existing threat actors...");
  const actors = await prisma.threatActor.findMany({
    where: { deprecated: false, revoked: false },
    select: { id: true, name: true, aliases: true },
  });

  const actorIndex = new Map<string, string>();
  for (const actor of actors) {
    actorIndex.set(normalizeForMatch(actor.name), actor.id);
    if (actor.aliases) {
      try {
        const aliases = JSON.parse(actor.aliases) as string[];
        for (const alias of aliases) {
          actorIndex.set(normalizeForMatch(alias), actor.id);
        }
      } catch {}
    }
  }
  console.log(`[*] ${actors.length} actors, ${actorIndex.size} name/alias keys`);

  function findActorId(groupName: string): string | null {
    const norm = normalizeForMatch(groupName);
    if (actorIndex.has(norm)) return actorIndex.get(norm)!;

    const folderKey = groupName.toLowerCase().replace(/\s+/g, "-");
    const customAliases =
      ALIAS_MAP[norm] || ALIAS_MAP[folderKey] || ALIAS_MAP[groupName.toLowerCase()];
    if (customAliases) {
      for (const alias of customAliases) {
        const aid = actorIndex.get(normalizeForMatch(alias));
        if (aid) return aid;
      }
    }

    for (const [key, id] of actorIndex) {
      if (key.includes(norm) || norm.includes(key)) {
        if (key.length > 3 && norm.length > 3) return id;
      }
    }
    return null;
  }

  // --- Phase 1: README link parsing ---
  console.log("\n[*] Phase 1: Parsing README report links...");
  const readmeResp = await fetch(README_URL);
  let readmeEntries: ReportEntry[] = [];
  if (readmeResp.ok) {
    readmeEntries = parseReadme(await readmeResp.text());
    console.log(`    Found ${readmeEntries.length} links in README`);
  }

  // --- Phase 2: GitHub API directory scan ---
  console.log("\n[*] Phase 2: Scanning repo subdirectories via GitHub API...");
  const dirs = await fetchTopLevelDirs();
  console.log(`    ${dirs.length} APT group directories found`);

  const dirEntries: ReportEntry[] = [];
  for (const dir of dirs) {
    const files = await fetchGithubDir(dir);
    for (const f of files) {
      if (f.type !== "file") continue;
      if (SKIP_FILES.has(f.name.toLowerCase())) continue;

      const ext = f.name.split(".").pop()?.toLowerCase() ?? "";
      if (!["pdf", "doc", "docx", "xlsx", "pptx", "html", "md", "txt", "csv"].includes(ext)) continue;

      dirEntries.push({
        group: dir,
        title: titleFromFilename(f.name),
        url: f.html_url,
        date: null,
      });
    }
    // Small delay to avoid rate limiting
    await new Promise(r => setTimeout(r, 200));
  }
  console.log(`    Found ${dirEntries.length} report files in subdirectories`);

  // --- Merge and deduplicate ---
  const allEntries = [...readmeEntries, ...dirEntries];
  const seenUrls = new Set<string>();
  const uniqueEntries: ReportEntry[] = [];
  for (const e of allEntries) {
    if (!seenUrls.has(e.url)) {
      seenUrls.add(e.url);
      uniqueEntries.push(e);
    }
  }
  console.log(`\n[*] Total unique entries: ${uniqueEntries.length}`);

  // --- Insert ---
  let created = 0;
  let linked = 0;
  let skipped = 0;
  const unmatched = new Set<string>();

  const grouped = new Map<string, ReportEntry[]>();
  for (const entry of uniqueEntries) {
    const key = entry.group;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key)!.push(entry);
  }

  for (const [group, reports] of grouped) {
    if (SKIP_DIRS.has(group.toLowerCase())) {
      skipped += reports.length;
      continue;
    }

    const actorId = findActorId(group);
    if (!actorId) {
      unmatched.add(group);
      skipped += reports.length;
      continue;
    }

    for (const report of reports) {
      try {
        const feedItem = await prisma.feedItem.upsert({
          where: { url: report.url },
          update: {},
          create: {
            title: report.title.slice(0, 500),
            url: report.url,
            source: "blackorbird/apt_report",
            summary: `APT report: ${group}`,
            publishedAt: report.date ? tryParseDate(report.date) : null,
            tags: JSON.stringify([group]),
          },
        });

        await prisma.actorFeedItem.upsert({
          where: { actorId_feedItemId: { actorId, feedItemId: feedItem.id } },
          update: {},
          create: { actorId, feedItemId: feedItem.id },
        });

        created++;
        linked++;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (!msg.includes("Unique constraint")) {
          console.error(`  [!] Error: ${report.url}: ${msg}`);
        }
      }
    }
  }

  if (unmatched.size > 0) {
    console.log(`\n[!] Unmatched groups (${unmatched.size}):`);
    for (const g of [...unmatched].sort()) {
      console.log(`    - ${g}`);
    }
  }

  await prisma.updateLog.create({
    data: {
      source: "blackorbird/apt_report",
      status: "completed",
      recordsProcessed: uniqueEntries.length,
      recordsCreated: created,
      recordsUpdated: linked,
      errorMessage: unmatched.size > 0
        ? `Unmatched: ${[...unmatched].join(", ")}`
        : null,
      completedAt: new Date(),
    },
  });

  console.log(`\n[*] Done:`);
  console.log(`    Total entries: ${uniqueEntries.length}`);
  console.log(`    Feed items created/linked: ${created}`);
  console.log(`    Skipped: ${skipped}`);
  console.log(`    Unmatched groups: ${unmatched.size}`);

  await prisma.$disconnect();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
