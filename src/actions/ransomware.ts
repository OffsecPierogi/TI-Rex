"use server";

import { prisma } from "@/lib/db";

export async function getRansomwareData() {
  const category = await prisma.category.findUnique({
    where: { slug: "ransomware" },
  });

  const ransomwareActors = category
    ? await prisma.categoryActor.findMany({
        where: { categoryId: category.id },
        include: {
          actor: {
            include: {
              _count: { select: { procedures: true, campaigns: true } },
            },
          },
        },
      })
    : [];

  const ransomwareAdvisories = await prisma.advisory.findMany({
    where: { knownRansomware: true },
    orderBy: { dateAdded: "desc" },
    take: 50,
  });

  const ransomwareTechniques = category
    ? await prisma.categoryTechnique.findMany({
        where: { categoryId: category.id },
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              _count: { select: { procedures: true, atomicTests: true } },
            },
          },
        },
      })
    : [];

  return {
    actors: ransomwareActors.map((ra) => ({
      id: ra.actor.id,
      name: ra.actor.name,
      externalId: ra.actor.externalId,
      procedureCount: ra.actor._count.procedures,
      campaignCount: ra.actor._count.campaigns,
    })),
    advisories: ransomwareAdvisories,
    techniques: ransomwareTechniques.map((rt) => ({
      id: rt.technique.id,
      externalId: rt.technique.externalId,
      name: rt.technique.name,
      procedureCount: rt.technique._count.procedures,
      atomicTestCount: rt.technique._count.atomicTests,
    })),
  };
}
