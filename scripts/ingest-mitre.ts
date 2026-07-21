import { prisma } from "../src/lib/db";
import { join } from "path";
import { existsSync } from "fs";
import {
  loadStixBundle,
  getExternalId,
  getExternalUrl,
  filterByType,
  filterByTypeIncludeAll,
  type StixObject,
} from "./utils/stix-parser";

const DATA_DIR = join(__dirname, "..", "data", "sources", "cti");

const MATRICES = [
  { name: "enterprise-attack", path: "enterprise-attack/enterprise-attack.json" },
  { name: "mobile-attack", path: "mobile-attack/mobile-attack.json" },
  { name: "ics-attack", path: "ics-attack/ics-attack.json" },
];

const TACTIC_ORDER: Record<string, number> = {
  "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
  "execution": 3, "persistence": 4, "privilege-escalation": 5,
  "defense-evasion": 6, "credential-access": 7, "discovery": 8,
  "lateral-movement": 9, "collection": 10, "command-and-control": 11,
  "exfiltration": 12, "impact": 13,
  // ICS-specific
  "inhibit-response-function": 14, "impair-process-control": 15,
  "evasion": 6,
};

async function ingestMatrix(matrixName: string, bundlePath: string) {
  if (!existsSync(bundlePath)) {
    console.log(`  [skip] ${bundlePath} not found`);
    return;
  }

  console.log(`\n  Loading ${matrixName}...`);
  const bundle = loadStixBundle(bundlePath);
  console.log(`  ${bundle.objects.length} total STIX objects`);

  // --- Tactics ---
  const tactics = filterByType(bundle, "x-mitre-tactic");
  console.log(`  Upserting ${tactics.length} tactics...`);
  for (const t of tactics) {
    const extId = getExternalId(t);
    if (!extId) continue;
    await prisma.tactic.upsert({
      where: { stixId: t.id },
      update: {
        name: t.name ?? "",
        shortName: t.x_mitre_shortname ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        orderIndex: TACTIC_ORDER[t.x_mitre_shortname ?? ""] ?? 99,
      },
      create: {
        stixId: t.id,
        externalId: extId,
        name: t.name ?? "",
        shortName: t.x_mitre_shortname ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        matrix: matrixName,
        orderIndex: TACTIC_ORDER[t.x_mitre_shortname ?? ""] ?? 99,
      },
    });
  }

  // --- Techniques (parents first, then sub-techniques) ---
  const allTechniques = filterByTypeIncludeAll(bundle, "attack-pattern");
  const parents = allTechniques.filter((t) => !t.x_mitre_is_subtechnique);
  const subs = allTechniques.filter((t) => t.x_mitre_is_subtechnique);

  console.log(`  Upserting ${parents.length} techniques + ${subs.length} sub-techniques...`);

  for (const t of parents) {
    const extId = getExternalId(t);
    if (!extId) continue;
    await prisma.technique.upsert({
      where: { stixId: t.id },
      update: {
        name: t.name ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        platforms: JSON.stringify(t.x_mitre_platforms ?? []),
        dataSources: t.x_mitre_data_sources ? JSON.stringify(t.x_mitre_data_sources) : null,
        detection: (t.x_mitre_detection as string) ?? null,
        deprecated: t.x_mitre_deprecated ?? false,
        revoked: t.revoked ?? false,
      },
      create: {
        stixId: t.id,
        externalId: extId,
        name: t.name ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        platforms: JSON.stringify(t.x_mitre_platforms ?? []),
        dataSources: t.x_mitre_data_sources ? JSON.stringify(t.x_mitre_data_sources) : null,
        detection: (t.x_mitre_detection as string) ?? null,
        isSubtechnique: false,
        matrix: matrixName,
        deprecated: t.x_mitre_deprecated ?? false,
        revoked: t.revoked ?? false,
      },
    });

    // Link to tactics
    if (t.kill_chain_phases) {
      for (const phase of t.kill_chain_phases) {
        const tactic = await prisma.tactic.findFirst({
          where: { shortName: phase.phase_name, matrix: matrixName },
        });
        if (tactic) {
          const technique = await prisma.technique.findUnique({ where: { stixId: t.id } });
          if (technique) {
            await prisma.tacticTechnique.upsert({
              where: { tacticId_techniqueId: { tacticId: tactic.id, techniqueId: technique.id } },
              update: {},
              create: { tacticId: tactic.id, techniqueId: technique.id },
            });
          }
        }
      }
    }
  }

  for (const t of subs) {
    const extId = getExternalId(t);
    if (!extId) continue;
    const parentExtId = extId.split(".")[0];
    const parent = await prisma.technique.findFirst({
      where: { externalId: parentExtId, matrix: matrixName },
    });

    await prisma.technique.upsert({
      where: { stixId: t.id },
      update: {
        name: t.name ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        platforms: JSON.stringify(t.x_mitre_platforms ?? []),
        dataSources: t.x_mitre_data_sources ? JSON.stringify(t.x_mitre_data_sources) : null,
        detection: (t.x_mitre_detection as string) ?? null,
        parentId: parent?.id ?? null,
        deprecated: t.x_mitre_deprecated ?? false,
        revoked: t.revoked ?? false,
      },
      create: {
        stixId: t.id,
        externalId: extId,
        name: t.name ?? "",
        description: t.description ?? "",
        url: getExternalUrl(t),
        platforms: JSON.stringify(t.x_mitre_platforms ?? []),
        dataSources: t.x_mitre_data_sources ? JSON.stringify(t.x_mitre_data_sources) : null,
        detection: (t.x_mitre_detection as string) ?? null,
        isSubtechnique: true,
        parentId: parent?.id ?? null,
        matrix: matrixName,
        deprecated: t.x_mitre_deprecated ?? false,
        revoked: t.revoked ?? false,
      },
    });

    if (t.kill_chain_phases) {
      for (const phase of t.kill_chain_phases) {
        const tactic = await prisma.tactic.findFirst({
          where: { shortName: phase.phase_name, matrix: matrixName },
        });
        if (tactic) {
          const technique = await prisma.technique.findUnique({ where: { stixId: t.id } });
          if (technique) {
            await prisma.tacticTechnique.upsert({
              where: { tacticId_techniqueId: { tacticId: tactic.id, techniqueId: technique.id } },
              update: {},
              create: { tacticId: tactic.id, techniqueId: technique.id },
            });
          }
        }
      }
    }
  }

  // --- Threat Actors (intrusion-set) ---
  const actors = filterByType(bundle, "intrusion-set");
  console.log(`  Upserting ${actors.length} threat actors...`);
  for (const a of actors) {
    const extId = getExternalId(a);
    if (!extId) continue;
    await prisma.threatActor.upsert({
      where: { stixId: a.id },
      update: {
        name: a.name ?? "",
        aliases: a.aliases ? JSON.stringify(a.aliases) : null,
        description: a.description ?? "",
        url: getExternalUrl(a),
        deprecated: a.x_mitre_deprecated ?? false,
        revoked: a.revoked ?? false,
      },
      create: {
        stixId: a.id,
        externalId: extId,
        name: a.name ?? "",
        aliases: a.aliases ? JSON.stringify(a.aliases) : null,
        description: a.description ?? "",
        url: getExternalUrl(a),
        matrix: matrixName,
        deprecated: a.x_mitre_deprecated ?? false,
        revoked: a.revoked ?? false,
      },
    });
  }

  // --- Malware ---
  const malwareList = filterByType(bundle, "malware");
  console.log(`  Upserting ${malwareList.length} malware entries...`);
  for (const m of malwareList) {
    const extId = getExternalId(m);
    if (!extId) continue;
    const labels = (m.labels as string[]) ?? [];
    const malwareType = labels.find((l) => l !== "malware") ?? labels[0] ?? null;
    await prisma.malware.upsert({
      where: { stixId: m.id },
      update: {
        name: m.name ?? "",
        aliases: m.aliases ? JSON.stringify(m.aliases) : null,
        description: m.description ?? "",
        type: malwareType,
        platforms: m.x_mitre_platforms ? JSON.stringify(m.x_mitre_platforms) : null,
        url: getExternalUrl(m),
      },
      create: {
        stixId: m.id,
        externalId: extId,
        name: m.name ?? "",
        aliases: m.aliases ? JSON.stringify(m.aliases) : null,
        description: m.description ?? "",
        type: malwareType,
        platforms: m.x_mitre_platforms ? JSON.stringify(m.x_mitre_platforms) : null,
        url: getExternalUrl(m),
      },
    });
  }

  // --- Tools ---
  const tools = filterByType(bundle, "tool");
  console.log(`  Upserting ${tools.length} tools...`);
  for (const t of tools) {
    const extId = getExternalId(t);
    if (!extId) continue;
    await prisma.tool.upsert({
      where: { stixId: t.id },
      update: {
        name: t.name ?? "",
        aliases: t.aliases ? JSON.stringify(t.aliases) : null,
        description: t.description ?? "",
        platforms: t.x_mitre_platforms ? JSON.stringify(t.x_mitre_platforms) : null,
        url: getExternalUrl(t),
      },
      create: {
        stixId: t.id,
        externalId: extId,
        name: t.name ?? "",
        aliases: t.aliases ? JSON.stringify(t.aliases) : null,
        description: t.description ?? "",
        platforms: t.x_mitre_platforms ? JSON.stringify(t.x_mitre_platforms) : null,
        url: getExternalUrl(t),
      },
    });
  }

  // --- Campaigns ---
  const campaigns = filterByType(bundle, "campaign");
  console.log(`  Upserting ${campaigns.length} campaigns...`);
  for (const c of campaigns) {
    const extId = getExternalId(c);
    if (!extId) continue;
    await prisma.campaign.upsert({
      where: { stixId: c.id },
      update: {
        name: c.name ?? "",
        description: c.description ?? "",
        firstSeen: c.first_seen ? new Date(c.first_seen) : null,
        lastSeen: c.last_seen ? new Date(c.last_seen) : null,
        url: getExternalUrl(c),
      },
      create: {
        stixId: c.id,
        externalId: extId,
        name: c.name ?? "",
        description: c.description ?? "",
        firstSeen: c.first_seen ? new Date(c.first_seen) : null,
        lastSeen: c.last_seen ? new Date(c.last_seen) : null,
        url: getExternalUrl(c),
      },
    });
  }

  // --- Relationships → Procedures + Campaign-Actor links ---
  const rels = bundle.objects.filter(
    (o) => o.type === "relationship" && !o.revoked
  );
  console.log(`  Processing ${rels.length} relationships...`);

  // Build lookup maps for STIX IDs → DB IDs
  const stixToTechnique = new Map<string, string>();
  const allTechniqueRows = await prisma.technique.findMany({
    where: { matrix: matrixName },
    select: { id: true, stixId: true },
  });
  for (const row of allTechniqueRows) stixToTechnique.set(row.stixId, row.id);

  const stixToActor = new Map<string, string>();
  const allActorRows = await prisma.threatActor.findMany({
    select: { id: true, stixId: true },
  });
  for (const row of allActorRows) stixToActor.set(row.stixId, row.id);

  const stixToMalware = new Map<string, string>();
  const allMalwareRows = await prisma.malware.findMany({
    select: { id: true, stixId: true },
  });
  for (const row of allMalwareRows) stixToMalware.set(row.stixId, row.id);

  const stixToTool = new Map<string, string>();
  const allToolRows = await prisma.tool.findMany({
    select: { id: true, stixId: true },
  });
  for (const row of allToolRows) stixToTool.set(row.stixId, row.id);

  const stixToCampaign = new Map<string, string>();
  const allCampaignRows = await prisma.campaign.findMany({
    select: { id: true, stixId: true },
  });
  for (const row of allCampaignRows) stixToCampaign.set(row.stixId, row.id);

  let procedureCount = 0;
  let campaignActorCount = 0;

  for (const rel of rels) {
    const sourceRef = rel.source_ref!;
    const targetRef = rel.target_ref!;

    if (rel.relationship_type === "uses") {
      const techniqueId = stixToTechnique.get(targetRef);
      if (!techniqueId) continue;

      const actorId = stixToActor.get(sourceRef);
      const malwareId = stixToMalware.get(sourceRef);
      const toolId = stixToTool.get(sourceRef);
      const campaignId = stixToCampaign.get(sourceRef);

      if (!actorId && !malwareId && !toolId && !campaignId) continue;

      try {
        await prisma.procedure.upsert({
          where: { stixId: rel.id },
          update: { description: rel.description ?? "" },
          create: {
            stixId: rel.id,
            actorId: actorId ?? null,
            malwareId: malwareId ?? null,
            toolId: toolId ?? null,
            campaignId: campaignId ?? null,
            techniqueId,
            description: rel.description ?? "",
          },
        });
        procedureCount++;
      } catch {
        // Skip duplicates or constraint violations
      }
    } else if (rel.relationship_type === "attributed-to") {
      const campaignId = stixToCampaign.get(sourceRef);
      const actorId = stixToActor.get(targetRef);
      if (campaignId && actorId) {
        try {
          await prisma.campaignActor.upsert({
            where: { campaignId_actorId: { campaignId, actorId } },
            update: {},
            create: { campaignId, actorId },
          });
          campaignActorCount++;
        } catch {
          // Skip
        }
      }
    }
  }

  console.log(`  Created/updated ${procedureCount} procedures, ${campaignActorCount} campaign-actor links`);
}

async function main() {
  const logEntry = await prisma.updateLog.create({
    data: { source: "mitre-attack", status: "running" },
  });

  try {
    for (const matrix of MATRICES) {
      const bundlePath = join(DATA_DIR, matrix.path);
      await ingestMatrix(matrix.name, bundlePath);
    }

    const counts = {
      tactics: await prisma.tactic.count(),
      techniques: await prisma.technique.count(),
      actors: await prisma.threatActor.count(),
      malware: await prisma.malware.count(),
      tools: await prisma.tool.count(),
      campaigns: await prisma.campaign.count(),
      procedures: await prisma.procedure.count(),
    };

    console.log("\n=== MITRE ATT&CK Ingestion Complete ===");
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
    console.error("MITRE ingestion failed:", err);
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
