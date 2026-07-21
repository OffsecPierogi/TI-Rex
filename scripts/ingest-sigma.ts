import { prisma } from "../src/lib/db";
import { ensureRepo } from "./utils/git-clone";
import { readdirSync, readFileSync, statSync } from "fs";
import { join, basename } from "path";

// SigmaHQ — community detection rules in Sigma format
// https://github.com/SigmaHQ/sigma
// Cloned/pulled on each update, parsed from YAML files

const SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git";
const SIGMA_DIR_NAME = "sigma";

const SEVERITY_MAP: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "low",
};

const ATTACK_ID_RE = /attack\.(t\d{4}(?:\.\d{3})?)/gi;
const MITRE_TAG_RE = /^attack\.(t\d{4}(?:\.\d{3})?)$/i;

interface SigmaRule {
  title: string;
  description?: string;
  status?: string;
  level?: string;
  tags?: string[];
  logsource?: {
    category?: string;
    product?: string;
    service?: string;
  };
  author?: string;
  date?: string;
}

function parseYamlSimple(content: string): SigmaRule {
  const result: SigmaRule = { title: "" };
  const lines = content.split("\n");

  for (const line of lines) {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("title:")) result.title = trimmed.slice(6).trim().replace(/^['"]|['"]$/g, "");
    if (trimmed.startsWith("description:")) result.description = trimmed.slice(12).trim().replace(/^['"]|['"]$/g, "");
    if (trimmed.startsWith("status:")) result.status = trimmed.slice(7).trim();
    if (trimmed.startsWith("level:")) result.level = trimmed.slice(6).trim();
    if (trimmed.startsWith("author:")) result.author = trimmed.slice(7).trim();
    if (trimmed.startsWith("date:")) result.date = trimmed.slice(5).trim();
  }

  const tags: string[] = [];
  let inTags = false;
  for (const line of lines) {
    if (/^tags:\s*$/.test(line.trimEnd())) { inTags = true; continue; }
    if (inTags) {
      if (line.match(/^\s+-\s+/)) {
        tags.push(line.replace(/^\s+-\s+/, "").trim());
      } else {
        inTags = false;
      }
    }
  }
  result.tags = tags;

  return result;
}

function extractTechniqueIds(tags: string[]): string[] {
  const ids: string[] = [];
  for (const tag of tags) {
    const m = tag.match(MITRE_TAG_RE);
    if (m) ids.push(m[1].toUpperCase());
  }
  return [...new Set(ids)];
}

function categorizeFromTags(tags: string[]): string | null {
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    if (lower.includes("credential_access")) return "credential-access";
    if (lower.includes("persistence")) return "persistence";
    if (lower.includes("privilege_escalation")) return "privilege-escalation";
    if (lower.includes("defense_evasion")) return "defense-evasion";
    if (lower.includes("lateral_movement")) return "lateral-movement";
    if (lower.includes("execution")) return "execution";
    if (lower.includes("discovery")) return "discovery";
    if (lower.includes("collection")) return "collection";
    if (lower.includes("exfiltration")) return "exfiltration";
    if (lower.includes("impact")) return "impact";
    if (lower.includes("initial_access")) return "initial-access";
    if (lower.includes("command_and_control")) return "c2";
  }
  return null;
}

function walkDir(dir: string, ext: string): string[] {
  const results: string[] = [];
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const full = join(dir, entry);
      try {
        const stat = statSync(full);
        if (stat.isDirectory()) {
          results.push(...walkDir(full, ext));
        } else if (entry.endsWith(ext)) {
          results.push(full);
        }
      } catch { /* skip inaccessible */ }
    }
  } catch { /* skip inaccessible */ }
  return results;
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "sigma-hq", status: "running" },
  });

  try {
    console.log("=== SigmaHQ Detection Rule Ingestion ===\n");

    console.log("Cloning/pulling SigmaHQ repository...");
    const repoDir = ensureRepo(SIGMA_REPO, SIGMA_DIR_NAME);

    const rulesDir = join(repoDir, "rules");
    console.log("Scanning for Sigma YAML files...");
    const yamlFiles = walkDir(rulesDir, ".yml");
    console.log(`  Found ${yamlFiles.length} rule files`);

    let created = 0;
    let skipped = 0;
    let errors = 0;

    for (const filePath of yamlFiles) {
      try {
        const content = readFileSync(filePath, "utf-8");
        const parsed = parseYamlSimple(content);

        if (!parsed.title) { skipped++; continue; }
        if (parsed.status === "deprecated" || parsed.status === "unsupported") { skipped++; continue; }

        const existing = await prisma.detectionRule.findFirst({
          where: { name: parsed.title, language: "sigma" },
        });
        if (existing) { skipped++; continue; }

        const techniqueIds = extractTechniqueIds(parsed.tags ?? []);
        let techniqueId: string | null = null;

        if (techniqueIds.length > 0) {
          const tech = await prisma.technique.findFirst({
            where: { externalId: techniqueIds[0] },
          });
          if (tech) techniqueId = tech.id;
        }

        const category = categorizeFromTags(parsed.tags ?? []);
        const severity = parsed.level ? SEVERITY_MAP[parsed.level] ?? null : null;

        await prisma.detectionRule.create({
          data: {
            name: parsed.title,
            description: parsed.description?.slice(0, 1000) || null,
            query: content.slice(0, 10000),
            language: "sigma",
            techniqueId,
            category,
            source: `SigmaHQ${parsed.author ? ` (${parsed.author.slice(0, 100)})` : ""}`,
            severity,
            tags: parsed.tags?.join(", ").slice(0, 500) || null,
          },
        });
        created++;
      } catch {
        errors++;
      }
    }

    console.log(`\n  Created: ${created}`);
    console.log(`  Skipped: ${skipped}`);
    console.log(`  Errors: ${errors}`);

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: yamlFiles.length,
        recordsCreated: created,
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("SigmaHQ ingestion failed:", err);
    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: { status: "error", errorMessage: String(err), completedAt: new Date() },
    });
  }
}

main().catch(console.error).finally(() => process.exit(0));
