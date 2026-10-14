import "dotenv/config";
import { prisma } from "../src/lib/db";
import { join } from "path";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { execSync } from "child_process";
import yaml from "js-yaml";

const DATA_DIR = join(__dirname, "..", "data", "sources", "atlas");
const YAML_URL =
  "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml";
const MATRIX_NAME = "atlas";

interface AtlasTactic {
  id: string;
  name: string;
  description: string;
  "created-date"?: string;
  "modified-date"?: string;
  "object-type": string;
}

interface AtlasTechnique {
  id: string;
  name: string;
  description: string;
  platforms?: string[];
  maturity?: string;
  "attack-reference"?: { id: string; url: string };
  "created-date"?: string;
  "modified-date"?: string;
  "object-type": string;
  references?: Array<{ title?: string; url?: string }>;
}

interface AtlasRelEntry {
  source: string;
  target: string;
  "relationship-type": string;
  description?: string;
}

interface AtlasData {
  tactics: Record<string, AtlasTactic>;
  techniques: Record<string, AtlasTechnique>;
  mitigations?: Record<string, unknown>;
  "case-studies"?: Record<string, unknown>;
  relationships?: Record<string, { achieves?: AtlasRelEntry[]; employs?: AtlasRelEntry[] }>;
}

function downloadAtlasYaml(): string {
  const filePath = join(DATA_DIR, "ATLAS-latest.yaml");
  if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
  }

  console.log("  Downloading ATLAS YAML...");
  let content: string;
  try {
    content = execSync(`curl -sL "${YAML_URL}"`, {
      encoding: "utf-8",
      timeout: 30_000,
    }).trim();
  } catch {
    if (existsSync(filePath)) {
      console.log("  Download failed, using cached copy");
      return filePath;
    }
    throw new Error("Failed to download ATLAS data and no cached copy exists");
  }

  // The file may be a redirect pointer (e.g. "ATLAS-2026.09.yaml")
  if (!content.includes("tactics:") && content.endsWith(".yaml")) {
    const redirectUrl = YAML_URL.replace("ATLAS-latest.yaml", content);
    content = execSync(`curl -sL "${redirectUrl}"`, {
      encoding: "utf-8",
      timeout: 60_000,
    });
  }

  writeFileSync(filePath, content, "utf-8");
  console.log("  Saved to", filePath);
  return filePath;
}

function loadAtlasData(filePath: string): AtlasData {
  const raw = readFileSync(filePath, "utf-8");
  return yaml.load(raw) as AtlasData;
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "mitre-atlas", status: "running" },
  });

  try {
    const filePath = downloadAtlasYaml();
    const data = loadAtlasData(filePath);

    // --- Tactics ---
    const tactics = data.tactics;
    const tacticIds = Object.keys(tactics);
    console.log(`  Upserting ${tacticIds.length} ATLAS tactics...`);

    const tacticIdToShortName = new Map<string, string>();
    for (let i = 0; i < tacticIds.length; i++) {
      const id = tacticIds[i];
      const t = tactics[id];
      const shortName = t.name.toLowerCase().replace(/\s+/g, "-");
      tacticIdToShortName.set(id, shortName);

      await prisma.tactic.upsert({
        where: { externalId: id },
        update: {
          name: t.name,
          shortName,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/tactics/${id}`,
          orderIndex: i,
        },
        create: {
          stixId: `x-mitre-tactic--atlas-${id}`,
          externalId: id,
          name: t.name,
          shortName,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/tactics/${id}`,
          matrix: MATRIX_NAME,
          orderIndex: i,
        },
      });
    }

    // --- Techniques ---
    const techniques = data.techniques;
    const techIds = Object.keys(techniques);
    const parents = techIds.filter((id) => {
      const stripped = id.replace("AML.T", "");
      return !stripped.includes(".");
    });
    const subs = techIds.filter((id) => {
      const stripped = id.replace("AML.T", "");
      return stripped.includes(".");
    });

    console.log(`  Upserting ${parents.length} techniques + ${subs.length} sub-techniques...`);

    // Parents first
    for (const id of parents) {
      const t = techniques[id];
      await prisma.technique.upsert({
        where: { externalId: id },
        update: {
          name: t.name,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/techniques/${id}`,
          platforms: JSON.stringify(t.platforms ?? []),
        },
        create: {
          stixId: `attack-pattern--atlas-${id}`,
          externalId: id,
          name: t.name,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/techniques/${id}`,
          platforms: JSON.stringify(t.platforms ?? []),
          isSubtechnique: false,
          matrix: MATRIX_NAME,
        },
      });
    }

    // Sub-techniques
    for (const id of subs) {
      const t = techniques[id];
      const parentExtId = id.split(".").slice(0, 1).join(".");
      // AML.T0000.000 → parent is AML.T0000
      const parentPrefix = id.substring(0, id.lastIndexOf("."));
      const parent = await prisma.technique.findFirst({
        where: { externalId: parentPrefix, matrix: MATRIX_NAME },
      });

      await prisma.technique.upsert({
        where: { externalId: id },
        update: {
          name: t.name,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/techniques/${id}`,
          platforms: JSON.stringify(t.platforms ?? []),
          parentId: parent?.id ?? null,
        },
        create: {
          stixId: `attack-pattern--atlas-${id}`,
          externalId: id,
          name: t.name,
          description: t.description ?? "",
          url: `https://atlas.mitre.org/techniques/${id}`,
          platforms: JSON.stringify(t.platforms ?? []),
          isSubtechnique: true,
          parentId: parent?.id ?? null,
          matrix: MATRIX_NAME,
        },
      });
    }

    // --- Tactic-Technique Links (from relationships.AML.T*.achieves) ---
    const relationships = data.relationships ?? {};
    let linkCount = 0;

    for (const [relKey, relVal] of Object.entries(relationships)) {
      if (!relKey.startsWith("AML.T")) continue;
      const achieves = relVal.achieves;
      if (!achieves) continue;

      for (const rel of achieves) {
        const tacticExtId = rel.target;
        const techExtId = rel.source;

        const tactic = await prisma.tactic.findFirst({
          where: { externalId: tacticExtId, matrix: MATRIX_NAME },
        });
        const technique = await prisma.technique.findFirst({
          where: { externalId: techExtId, matrix: MATRIX_NAME },
        });

        if (tactic && technique) {
          await prisma.tacticTechnique.upsert({
            where: {
              tacticId_techniqueId: {
                tacticId: tactic.id,
                techniqueId: technique.id,
              },
            },
            update: {},
            create: { tacticId: tactic.id, techniqueId: technique.id },
          });
          linkCount++;
        }
      }
    }

    console.log(`  Created ${linkCount} tactic-technique links`);

    // --- Case Study → Technique links as Procedures ---
    let caseStudyCount = 0;
    const caseStudies = data["case-studies"] ?? {};

    for (const [csKey, csVal] of Object.entries(relationships)) {
      if (!csKey.startsWith("AML.CS")) continue;
      const employs = (csVal as { employs?: AtlasRelEntry[] }).employs;
      if (!employs) continue;

      const cs = caseStudies[csKey] as { name?: string; description?: string } | undefined;
      for (const rel of employs) {
        const technique = await prisma.technique.findFirst({
          where: { externalId: rel.target, matrix: MATRIX_NAME },
        });
        if (!technique) continue;

        const stixId = `relationship--atlas-${csKey}-${rel.target}`;
        const desc = rel.description
          ? `[${cs?.name ?? csKey}] ${rel.description}`
          : `Case study ${csKey} employs ${rel.target}`;

        try {
          await prisma.procedure.upsert({
            where: { stixId },
            update: { description: desc },
            create: {
              stixId,
              techniqueId: technique.id,
              description: desc,
            },
          });
          caseStudyCount++;
        } catch {
          // Skip constraint violations
        }
      }
    }

    console.log(`  Created ${caseStudyCount} case study procedure links`);

    const counts = {
      tactics: await prisma.tactic.count({ where: { matrix: MATRIX_NAME } }),
      techniques: await prisma.technique.count({ where: { matrix: MATRIX_NAME } }),
    };

    console.log("\n=== MITRE ATLAS Ingestion Complete ===");
    console.log(JSON.stringify(counts, null, 2));

    await prisma.updateLog.update({
      where: { id: logEntry.id },
      data: {
        status: "success",
        recordsProcessed: Object.values(counts).reduce((a, b) => a + b, 0),
        completedAt: new Date(),
      },
    });
  } catch (err) {
    console.error("ATLAS ingestion failed:", err);
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

main()
  .catch(console.error)
  .finally(() => process.exit(0));
