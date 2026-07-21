import "dotenv/config";
import { prisma } from "../src/lib/db";
import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, relative } from "path";

const DATA_DIR = join(__dirname, "..", "data", "sources");

interface SourceConfig {
  name: string;
  dir: string;
  prefix: string;
  extensions: string[];
  includeDirs?: string[];
  excludeDirs?: string[];
  excludePatterns?: string[];
  categoryFromPath: (filePath: string) => string;
}

const SOURCES: SourceConfig[] = [
  {
    name: "YARA-Rules/rules",
    dir: join(DATA_DIR, "yara-rules"),
    prefix: "YR",
    extensions: [".yar"],
    includeDirs: ["malware", "webshells", "exploit_kits", "cve_rules", "maldocs", "antidebug_antivm", "capabilities", "crypto"],
    excludePatterns: ["_index.yar"],
    categoryFromPath: (fp) => {
      const parts = fp.split("/");
      const dirMap: Record<string, string> = {
        malware: "malware", webshells: "webshell", exploit_kits: "exploit-kit",
        cve_rules: "cve", maldocs: "maldoc", antidebug_antivm: "evasion",
        capabilities: "capability", crypto: "crypto",
      };
      for (const part of parts) {
        if (dirMap[part]) return dirMap[part];
      }
      return "malware";
    },
  },
  {
    name: "Neo23x0/signature-base",
    dir: join(DATA_DIR, "signature-base"),
    prefix: "SB",
    extensions: [".yar"],
    includeDirs: ["yara"],
    excludePatterns: ["_index.yar"],
    categoryFromPath: (fp) => {
      const fname = fp.split("/").pop() || "";
      if (fname.startsWith("apt_")) return "apt-tool";
      if (fname.startsWith("crime_")) return "malware";
      if (fname.startsWith("gen_")) return "malware";
      if (fname.startsWith("expl_") || fname.startsWith("exploit_")) return "exploit-kit";
      if (fname.startsWith("mal_")) return "malware";
      if (fname.startsWith("vul_")) return "cve";
      if (fname.startsWith("hktl_")) return "apt-tool";
      if (fname.startsWith("webshell_")) return "webshell";
      if (fname.startsWith("susp_")) return "evasion";
      return "malware";
    },
  },
  {
    name: "ReversingLabs",
    dir: join(DATA_DIR, "reversinglabs-yara"),
    prefix: "RL",
    extensions: [".yara"],
    includeDirs: ["yara"],
    categoryFromPath: (fp) => {
      const dirMap: Record<string, string> = {
        ransomware: "ransomware", backdoor: "rat", trojan: "malware",
        infostealer: "stealer", virus: "malware", certificate: "evasion",
        downloader: "malware", exploit: "exploit-kit", pua: "malware",
        rootkit: "rat",
      };
      const parts = fp.split("/");
      for (const part of parts) {
        if (dirMap[part]) return dirMap[part];
      }
      return "malware";
    },
  },
];

const SEVERITY_MAP: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low",
  informational: "low", info: "low",
};

interface ParsedRule {
  name: string;
  tags: string[];
  meta: Record<string, string>;
  fullText: string;
  sourceFile: string;
  category: string;
}

function parseYaraFile(filePath: string, category: string): ParsedRule[] {
  const content = readFileSync(filePath, "utf-8");
  const rules: ParsedRule[] = [];
  const ruleRegex = /^(private\s+)?rule\s+(\w+)\s*(?::\s*([^\n{]+))?\s*\{/gm;
  let match: RegExpExecArray | null;

  while ((match = ruleRegex.exec(content)) !== null) {
    if (match[1]) continue; // skip private rules

    const ruleName = match[2];
    const ruleTags = match[3]
      ? match[3].trim().split(/\s+/).filter((t) => t.length > 0)
      : [];

    let braceDepth = 0;
    let ruleEnd = -1;
    let foundFirstBrace = false;

    for (let i = match.index; i < content.length; i++) {
      if (content[i] === "{") { braceDepth++; foundFirstBrace = true; }
      else if (content[i] === "}") {
        braceDepth--;
        if (foundFirstBrace && braceDepth === 0) { ruleEnd = i + 1; break; }
      }
    }
    if (ruleEnd === -1) continue;

    const fullText = content.slice(match.index, ruleEnd).trim();
    const meta = extractMeta(fullText);
    rules.push({ name: ruleName, tags: ruleTags, meta, fullText, sourceFile: filePath, category });
  }
  return rules;
}

function extractMeta(ruleText: string): Record<string, string> {
  const meta: Record<string, string> = {};
  const metaMatch = ruleText.match(/meta\s*:\s*\n([\s\S]*?)(?=\n\s*(strings|condition)\s*:)/);
  if (!metaMatch) return meta;
  for (const line of metaMatch[1].split("\n")) {
    const kv = line.match(/^\s*(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"/);
    if (kv) meta[kv[1].toLowerCase()] = kv[2].replace(/\\"/g, '"').replace(/\\\\/g, "\\");
  }
  return meta;
}

function findFiles(dir: string, extensions: string[], excludePatterns?: string[]): string[] {
  const files: string[] = [];
  try {
    for (const entry of readdirSync(dir)) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) {
        files.push(...findFiles(fullPath, extensions, excludePatterns));
      } else if (extensions.some((ext) => entry.endsWith(ext))) {
        if (excludePatterns && excludePatterns.some((p) => entry.includes(p))) continue;
        files.push(fullPath);
      }
    }
  } catch { /* skip inaccessible */ }
  return files;
}

function guessSeverity(rule: ParsedRule): string {
  if (rule.meta.severity) {
    const s = SEVERITY_MAP[rule.meta.severity.toLowerCase()];
    if (s) return s;
  }
  const combined = `${rule.name} ${rule.tags.join(" ")} ${rule.category}`.toLowerCase();
  if (/apt|ransomware|rat|backdoor|rootkit/.test(combined)) return "critical";
  if (/trojan|stealer|webshell|exploit/.test(combined)) return "high";
  return "medium";
}

function guessCategory(rule: ParsedRule): string {
  const name = rule.name.toLowerCase();
  if (name.startsWith("apt_") || name.includes("_apt")) return "apt-tool";
  if (/ransomware|ransom/.test(name)) return "ransomware";
  if (/^rat_|backdoor/.test(name)) return "rat";
  if (/webshell/.test(name)) return "webshell";
  if (/stealer|infostealer/.test(name)) return "stealer";
  if (/exploit|cve[_-]/.test(name)) return "exploit-kit";
  if (/maldoc/.test(name)) return "maldoc";
  if (/packer|upx|vmprotect/.test(name)) return "packer";
  return rule.category;
}

async function main() {
  console.log("=== TI-Rex YARA Rule Ingestion (Multi-Source) ===\n");

  const allMalware = await prisma.malware.findMany({ select: { id: true, name: true, aliases: true } });
  const malwareLookup = new Map<string, string>();
  for (const m of allMalware) {
    malwareLookup.set(m.name.toLowerCase(), m.id);
    if (m.aliases) {
      for (const alias of m.aliases.split(",")) {
        malwareLookup.set(alias.trim().toLowerCase(), m.id);
      }
    }
  }

  const allTechniques = await prisma.technique.findMany({ select: { id: true, externalId: true } });
  const techniqueLookup = new Map<string, string>();
  for (const t of allTechniques) techniqueLookup.set(t.externalId, t.id);

  let grandTotal = 0;

  for (const source of SOURCES) {
    if (!existsSync(source.dir)) {
      console.log(`[${source.name}] Directory not found, skipping`);
      continue;
    }

    console.log(`\n=== ${source.name} ===`);

    const searchDirs = source.includeDirs
      ? source.includeDirs.map((d) => join(source.dir, d))
      : [source.dir];

    let allFiles: string[] = [];
    for (const dir of searchDirs) {
      if (existsSync(dir)) {
        allFiles.push(...findFiles(dir, source.extensions, source.excludePatterns));
      }
    }

    if (source.excludeDirs) {
      allFiles = allFiles.filter((f) => !source.excludeDirs!.some((d) => f.includes(`/${d}/`)));
    }

    console.log(`  Found ${allFiles.length} files`);

    let parsed = 0;
    let ingested = 0;
    let errors = 0;

    for (const file of allFiles) {
      let rules: ParsedRule[];
      try {
        const cat = source.categoryFromPath(relative(source.dir, file));
        rules = parseYaraFile(file, cat);
      } catch { errors++; continue; }

      parsed += rules.length;

      for (const rule of rules) {
        try {
          let malwareId: string | null = null;
          for (const word of rule.name.split("_")) {
            if (word.length > 2) {
              const found = malwareLookup.get(word.toLowerCase());
              if (found) { malwareId = found; break; }
            }
          }

          let techniqueId: string | null = null;
          const techRef = rule.meta.mitre_att || rule.meta.attack_technique || rule.meta.technique;
          if (techRef) {
            const tMatch = techRef.match(/T\d{4}(?:\.\d{3})?/);
            if (tMatch) techniqueId = techniqueLookup.get(tMatch[0]) || null;
          }

          const category = guessCategory(rule);
          const severity = guessSeverity(rule);
          const author = rule.meta.author || rule.meta.source || source.name;
          const description = rule.meta.description || rule.meta.info || `${category} detection: ${rule.name}`;
          const reference = rule.meta.reference || rule.meta.url || rule.meta.link || null;
          const tags = [...rule.tags, source.prefix.toLowerCase()].filter(Boolean).join(",");
          const uniqueName = `${source.prefix}_${rule.name}`;

          await prisma.yaraRule.upsert({
            where: { name: uniqueName },
            update: { description, rule: rule.fullText, category, author, reference, tags, severity, malwareId, techniqueId },
            create: { name: uniqueName, description, rule: rule.fullText, category, author, reference, tags, severity, malwareId, techniqueId },
          });
          ingested++;
        } catch (err: any) {
          if (err.code !== "P2002") errors++;
        }
      }
    }

    console.log(`  Parsed: ${parsed}, Ingested: ${ingested}, Errors: ${errors}`);
    grandTotal += ingested;
  }

  const total = await prisma.yaraRule.count();
  console.log(`\n=== Done. Ingested ${grandTotal} rules. Total in DB: ${total} ===`);
  await prisma.$disconnect();
}

main().catch((e) => { console.error(e); prisma.$disconnect(); process.exit(1); });
