"use server";

import { prisma } from "@/lib/db";

export async function getMatrixData(matrixName: string = "enterprise-attack") {
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
              _count: { select: { children: true, procedures: true } },
            },
          },
        },
      },
    },
  });

  return tactics.map((tactic) => ({
    id: tactic.id,
    name: tactic.name,
    shortName: tactic.shortName,
    externalId: tactic.externalId,
    techniques: tactic.techniques
      .map((tt) => tt.technique)
      .filter((t) => !t.isSubtechnique && !t.deprecated && !t.revoked)
      .sort((a, b) => a.externalId.localeCompare(b.externalId))
      .map((t) => ({
        id: t.id,
        externalId: t.externalId,
        name: t.name,
        subCount: t._count.children,
        procedureCount: t._count.procedures,
      })),
  }));
}

export interface LayerHighlight {
  techniqueId: string;
  score: number;
  comment: string;
}

export async function getActorLayer(actorId: string): Promise<{ name: string; color: string; highlights: LayerHighlight[] }> {
  const actor = await prisma.threatActor.findUnique({
    where: { id: actorId },
    select: {
      name: true,
      procedures: {
        select: { technique: { select: { externalId: true } } },
      },
    },
  });
  if (!actor) return { name: "", color: "#e60000", highlights: [] };

  const counts = new Map<string, number>();
  for (const p of actor.procedures) {
    counts.set(p.technique.externalId, (counts.get(p.technique.externalId) || 0) + 1);
  }

  return {
    name: actor.name,
    color: "#e60000",
    highlights: [...counts.entries()].map(([techniqueId, score]) => ({
      techniqueId,
      score,
      comment: `${score} procedure(s)`,
    })),
  };
}

export async function getMalwareLayer(malwareId: string): Promise<{ name: string; color: string; highlights: LayerHighlight[] }> {
  const malware = await prisma.malware.findUnique({
    where: { id: malwareId },
    select: {
      name: true,
      procedures: {
        select: { technique: { select: { externalId: true } } },
      },
    },
  });
  if (!malware) return { name: "", color: "#9b59b6", highlights: [] };

  const counts = new Map<string, number>();
  for (const p of malware.procedures) {
    counts.set(p.technique.externalId, (counts.get(p.technique.externalId) || 0) + 1);
  }

  return {
    name: malware.name,
    color: "#9b59b6",
    highlights: [...counts.entries()].map(([techniqueId, score]) => ({
      techniqueId,
      score,
      comment: `${score} procedure(s)`,
    })),
  };
}

export async function getCategoryLayer(slug: string): Promise<{ name: string; color: string; highlights: LayerHighlight[] }> {
  const category = await prisma.category.findUnique({
    where: { slug },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              externalId: true,
              _count: { select: { procedures: true } },
            },
          },
        },
      },
    },
  });
  if (!category) return { name: "", color: "#3498db", highlights: [] };

  return {
    name: category.name,
    color: category.color ?? "#3498db",
    highlights: category.techniques.map((ct) => ({
      techniqueId: ct.technique.externalId,
      score: ct.technique._count.procedures || 1,
      comment: `${ct.technique._count.procedures} procedure(s)`,
    })),
  };
}

export async function getComparisonLayer(actorIds: string[]): Promise<{ name: string; color: string; highlights: LayerHighlight[] }> {
  const actors = await prisma.threatActor.findMany({
    where: { id: { in: actorIds } },
    select: {
      name: true,
      procedures: {
        select: { technique: { select: { externalId: true } } },
      },
    },
  });

  const techActors = new Map<string, Set<string>>();
  for (const actor of actors) {
    for (const p of actor.procedures) {
      if (!techActors.has(p.technique.externalId)) {
        techActors.set(p.technique.externalId, new Set());
      }
      techActors.get(p.technique.externalId)!.add(actor.name);
    }
  }

  return {
    name: actors.map((a) => a.name).join(" vs "),
    color: "#e67e22",
    highlights: [...techActors.entries()].map(([techniqueId, actorSet]) => ({
      techniqueId,
      score: actorSet.size,
      comment: `Used by: ${[...actorSet].join(", ")}`,
    })),
  };
}
