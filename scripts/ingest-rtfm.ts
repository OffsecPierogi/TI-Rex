import "dotenv/config";
import { prisma } from "../src/lib/db";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

const DATA_DIR = join(__dirname, "..", "data", "sources", "rtfm", "updates");
const UPDATE_FILES = ["1.txt", "2.txt", "3.txt", "4.txt", "5.txt"];

const PLATFORM_TAGS = new Set([
  "linux", "windows", "cisco", "apple", "solaris", "android",
  "osx", "ios", "bsd", "freebsd", "unix", "macos",
]);

const TAG_TO_TECHNIQUE: Record<string, string> = {
  "brute force": "T1110",
  "sql injection": "T1190",
  "xss": "T1059.007",
  "buffer overflow": "T1203",
  "password cracking": "T1110.002",
  "credential dumping": "T1003",
  "pass the hash": "T1550.002",
  "privilege escalation": "T1068",
  "lateral movement": "T1021",
  "port scanning": "T1046",
  "dns": "T1071.004",
  "phishing": "T1566",
  "keylogger": "T1056.001",
  "persistence": "T1547",
  "exfiltration": "T1041",
  "data exfiltration": "T1041",
  "reverse shell": "T1059",
  "web shell": "T1505.003",
  "tunneling": "T1572",
  "process injection": "T1055",
};

interface RtfmEntry {
  command: string;
  description: string;
  author: string;
  tags: string[];
  references: string[];
}

function parseUpdateFile(filePath: string): RtfmEntry[] {
  const content = readFileSync(filePath, "utf-8");
  const lines = content.split("\n");
  const entries: RtfmEntry[] = [];

  let i = 0;
  while (i < lines.length) {
    if (lines[i].trim() === "" || lines[i].trim() === "EOR") {
      i++;
      continue;
    }

    const command = lines[i]?.trim();
    if (!command) { i++; continue; }

    const description = lines[i + 1]?.trim() || "";
    const author = lines[i + 2]?.trim() || "?";
    i += 3;

    if (i < lines.length && lines[i].trim() === "EOC") {
      i++;
    } else {
      continue;
    }

    const tags: string[] = [];
    while (i < lines.length && lines[i].trim() !== "EOT") {
      const tag = lines[i].trim();
      if (tag) tags.push(tag.toLowerCase());
      i++;
    }
    if (i < lines.length) i++; // skip EOT

    const references: string[] = [];
    while (i < lines.length && lines[i].trim() !== "EOR") {
      const ref = lines[i].trim();
      if (ref) references.push(ref);
      i++;
    }
    if (i < lines.length) i++; // skip EOR

    if (command && command !== "EOC" && command !== "EOT" && command !== "EOR") {
      entries.push({ command, description, author, tags, references });
    }
  }

  return entries;
}

function derivePlatform(tags: string[]): string | null {
  const platforms = tags.filter((t) => PLATFORM_TAGS.has(t));
  if (platforms.length === 0) return null;
  return platforms.map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join(", ");
}

async function findTechniqueId(tags: string[]): Promise<string | null> {
  for (const tag of tags) {
    const extId = TAG_TO_TECHNIQUE[tag];
    if (extId) {
      const technique = await prisma.technique.findFirst({
        where: { externalId: { startsWith: extId } },
        select: { id: true },
      });
      if (technique) return technique.id;
    }
  }
  return null;
}

async function main() {
  console.log("=== RTFM Command Ingestion ===\n");
  const start = Date.now();

  let totalParsed = 0;
  let totalCreated = 0;
  let totalSkipped = 0;

  for (const file of UPDATE_FILES) {
    const filePath = join(DATA_DIR, file);
    if (!existsSync(filePath)) {
      console.log(`  Skipping ${file} — not found`);
      continue;
    }

    const entries = parseUpdateFile(filePath);
    console.log(`  Parsed ${file}: ${entries.length} commands`);
    totalParsed += entries.length;

    for (const entry of entries) {
      const platform = derivePlatform(entry.tags);
      const techniqueId = await findTechniqueId(entry.tags);
      const nonPlatformTags = entry.tags.filter((t) => !PLATFORM_TAGS.has(t));

      try {
        await prisma.offensiveCommand.upsert({
          where: {
            command_source: {
              command: entry.command,
              source: "rtfm",
            },
          },
          update: {
            description: entry.description || null,
            author: entry.author === "?" ? null : entry.author,
            tags: nonPlatformTags.length > 0 ? JSON.stringify(nonPlatformTags) : null,
            references: entry.references.length > 0 ? JSON.stringify(entry.references) : null,
            platform,
            techniqueId,
          },
          create: {
            command: entry.command,
            description: entry.description || null,
            author: entry.author === "?" ? null : entry.author,
            source: "rtfm",
            tags: nonPlatformTags.length > 0 ? JSON.stringify(nonPlatformTags) : null,
            references: entry.references.length > 0 ? JSON.stringify(entry.references) : null,
            platform,
            techniqueId,
          },
        });
        totalCreated++;
      } catch (err: any) {
        if (err.code === "P2002") {
          totalSkipped++;
        } else {
          console.error(`  Error on command "${entry.command.substring(0, 50)}...":`, err.message);
          totalSkipped++;
        }
      }
    }
  }

  console.log(`\n  Total parsed: ${totalParsed}`);
  console.log(`  Upserted: ${totalCreated}`);
  console.log(`  Skipped/errors: ${totalSkipped}`);

  await prisma.updateLog.create({
    data: {
      source: "rtfm",
      status: "success",
      recordsProcessed: totalParsed,
      recordsCreated: totalCreated,
      completedAt: new Date(),
    },
  });

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`\n  Done in ${elapsed}s`);
  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error("RTFM ingestion failed:", err);
  await prisma.$disconnect();
  process.exit(1);
});
