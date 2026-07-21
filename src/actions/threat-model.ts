"use server";

import { prisma } from "@/lib/db";
import { STACK_COMPONENTS, INDUSTRY_PROFILES, type StackComponent } from "@/lib/threat-model-data";

export async function getStackAnalysis(componentIds: string[]) {
  const selected = STACK_COMPONENTS.filter((c) => componentIds.includes(c.id));
  if (selected.length === 0) return null;

  const allPlatforms = [...new Set(selected.flatMap((c) => c.platforms))].filter(Boolean);
  const allKeywords = [...new Set(selected.flatMap((c) => c.techniqueKeywords))];
  const allTechniqueIds = [...new Set(selected.flatMap((c) => c.techniqueIds))];
  const allActorKeywords = [...new Set(selected.flatMap((c) => c.actorKeywords))].filter(Boolean);

  const techWhere: unknown[] = [];
  if (allTechniqueIds.length > 0) techWhere.push({ externalId: { in: allTechniqueIds } });
  if (allPlatforms.length > 0) {
    for (const p of allPlatforms) techWhere.push({ platforms: { contains: p } });
  }
  for (const kw of allKeywords.slice(0, 15)) {
    techWhere.push({ description: { contains: kw } });
  }

  const techniques = await prisma.technique.findMany({
    where: { OR: techWhere, deprecated: false, revoked: false } as never,
    include: {
      tactics: { include: { tactic: { select: { name: true, shortName: true } } } },
      _count: { select: { atomicTests: true, detections: true } },
    },
    orderBy: { externalId: "asc" },
    take: 300,
  });

  const actorWhere: unknown[] = [];
  for (const kw of allActorKeywords) {
    actorWhere.push({ description: { contains: kw } });
  }

  const actors = actorWhere.length > 0
    ? await prisma.threatActor.findMany({
        where: { OR: actorWhere, deprecated: false, revoked: false } as never,
        select: { id: true, name: true, country: true, externalId: true, description: true },
        take: 50,
      })
    : [];

  const withAtomics = techniques.filter((t) => t._count.atomicTests > 0).length;
  const withDetections = techniques.filter((t) => t._count.detections > 0).length;
  const gaps = techniques.filter((t) => t._count.atomicTests > 0 && t._count.detections === 0).length;

  const byTactic: Record<string, typeof techniques> = {};
  for (const t of techniques) {
    for (const tt of t.tactics) {
      const name = tt.tactic.name;
      if (!byTactic[name]) byTactic[name] = [];
      byTactic[name].push(t);
    }
  }

  return {
    components: selected,
    techniques: techniques.map((t) => ({
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      platforms: JSON.parse(t.platforms) as string[],
      tactics: t.tactics.map((tt) => tt.tactic.name),
      atomicTests: t._count.atomicTests,
      detections: t._count.detections,
    })),
    actors,
    stats: {
      totalTechniques: techniques.length,
      totalActors: actors.length,
      withAtomics,
      withDetections,
      gaps,
      coverage: withAtomics > 0 ? Math.round((withDetections / techniques.length) * 100) : 0,
    },
    byTactic: Object.entries(byTactic).map(([tactic, techs]) => ({
      tactic,
      count: techs.length,
    })),
  };
}

export async function getIndustryAnalysis(industryId: string) {
  const profile = INDUSTRY_PROFILES.find((p) => p.id === industryId);
  if (!profile) return null;

  const actorWhere: unknown[] = [];
  if (profile.actorCountries.length > 0) {
    actorWhere.push({ country: { in: profile.actorCountries } });
  }
  for (const kw of profile.actorKeywords) {
    actorWhere.push({ description: { contains: kw } });
  }

  const actors = actorWhere.length > 0
    ? await prisma.threatActor.findMany({
        where: { OR: actorWhere, deprecated: false, revoked: false } as never,
        select: { id: true, name: true, country: true, externalId: true },
        orderBy: { name: "asc" },
        take: 80,
      })
    : [];

  const techWhere: unknown[] = [];
  for (const kw of profile.techniqueKeywords) {
    techWhere.push({ description: { contains: kw } });
  }
  if (profile.techniqueCategories.length > 0) {
    techWhere.push({ categories: { some: { category: { slug: { in: profile.techniqueCategories } } } } });
  }

  const techniques = techWhere.length > 0
    ? await prisma.technique.findMany({
        where: { OR: techWhere, deprecated: false, revoked: false } as never,
        include: {
          tactics: { include: { tactic: { select: { name: true } } } },
          _count: { select: { atomicTests: true, detections: true } },
        },
        orderBy: { externalId: "asc" },
        take: 300,
      })
    : [];

  const withDetections = techniques.filter((t) => t._count.detections > 0).length;

  return {
    profile,
    actors,
    techniques: techniques.map((t) => ({
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      tactics: t.tactics.map((tt) => tt.tactic.name),
      atomicTests: t._count.atomicTests,
      detections: t._count.detections,
    })),
    stats: {
      totalActors: actors.length,
      totalTechniques: techniques.length,
      withDetections,
      coverage: techniques.length > 0 ? Math.round((withDetections / techniques.length) * 100) : 0,
    },
  };
}

export async function getStackComponents() {
  return STACK_COMPONENTS;
}

export async function getIndustryProfiles() {
  return INDUSTRY_PROFILES;
}
