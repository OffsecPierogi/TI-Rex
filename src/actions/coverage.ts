"use server";

import { prisma } from "@/lib/db";

export async function getCoverageData(matrixName: string = "enterprise-attack") {
  const tactics = await prisma.tactic.findMany({
    where: { matrix: matrixName },
    orderBy: { orderIndex: "asc" },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              isSubtechnique: true,
              deprecated: true,
              revoked: true,
              _count: { select: { detections: true, children: true } },
            },
          },
        },
      },
    },
  });

  const result = tactics.map((tactic) => {
    const techniques = tactic.techniques
      .map((tt) => tt.technique)
      .filter((t) => !t.isSubtechnique && !t.deprecated && !t.revoked)
      .sort((a, b) => a.externalId.localeCompare(b.externalId))
      .map((t) => ({
        id: t.id,
        externalId: t.externalId,
        name: t.name,
        detectionCount: t._count.detections,
      }));

    return {
      id: tactic.id,
      name: tactic.name,
      shortName: tactic.shortName,
      externalId: tactic.externalId,
      techniques,
    };
  });

  // Deduplicate technique counts since a technique can appear under multiple tactics
  const seenTechniques = new Set<string>();
  let dedupTotal = 0;
  let dedupCovered = 0;
  let dedupDetections = 0;

  for (const tactic of result) {
    for (const tech of tactic.techniques) {
      if (!seenTechniques.has(tech.id)) {
        seenTechniques.add(tech.id);
        dedupTotal++;
        dedupDetections += tech.detectionCount;
        if (tech.detectionCount > 0) dedupCovered++;
      }
    }
  }

  const uncoveredTechniques = dedupTotal - dedupCovered;
  const coveragePercent = dedupTotal > 0 ? Math.round((dedupCovered / dedupTotal) * 100) : 0;
  const avgDetectionsPerTechnique = dedupTotal > 0
    ? Math.round((dedupDetections / dedupTotal) * 10) / 10
    : 0;

  return {
    tactics: result,
    stats: {
      totalTechniques: dedupTotal,
      coveredTechniques: dedupCovered,
      uncoveredTechniques,
      coveragePercent,
      avgDetectionsPerTechnique,
    },
  };
}

export async function getTechniqueDetections(techniqueId: string) {
  const technique = await prisma.technique.findUnique({
    where: { id: techniqueId },
    include: {
      detections: {
        orderBy: { name: "asc" },
      },
      children: {
        where: { deprecated: false, revoked: false },
        select: {
          id: true,
          externalId: true,
          name: true,
          _count: { select: { detections: true } },
        },
        orderBy: { externalId: "asc" },
      },
      tactics: {
        include: {
          tactic: { select: { id: true, name: true, shortName: true } },
        },
      },
    },
  });

  if (!technique) return null;

  const coveredSubs = technique.children.filter((c) => c._count.detections > 0).length;

  return {
    id: technique.id,
    externalId: technique.externalId,
    name: technique.name,
    description: technique.description,
    platforms: technique.platforms,
    tactics: technique.tactics.map((tt) => tt.tactic),
    detections: technique.detections.map((d) => ({
      id: d.id,
      name: d.name,
      description: d.description,
      query: d.query,
      language: d.language,
      severity: d.severity,
      source: d.source,
      category: d.category,
    })),
    subTechniques: {
      total: technique.children.length,
      covered: coveredSubs,
      items: technique.children.map((c) => ({
        id: c.id,
        externalId: c.externalId,
        name: c.name,
        detectionCount: c._count.detections,
      })),
    },
  };
}
