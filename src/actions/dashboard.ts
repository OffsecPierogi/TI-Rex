"use server";

import { prisma } from "@/lib/db";

export async function getDashboardStats() {
  const [tactics, techniques, actors, malware, tools, campaigns, procedures, atomicTests, advisories, iocs] =
    await Promise.all([
      prisma.tactic.count(),
      prisma.technique.count(),
      prisma.threatActor.count(),
      prisma.malware.count(),
      prisma.tool.count(),
      prisma.campaign.count(),
      prisma.procedure.count(),
      prisma.atomicTest.count(),
      prisma.advisory.count(),
      prisma.iOC.count(),
    ]);

  return { tactics, techniques, actors, malware, tools, campaigns, procedures, atomicTests, advisories, iocs };
}

export async function getRecentUpdates() {
  return prisma.updateLog.findMany({
    orderBy: { startedAt: "desc" },
    take: 10,
  });
}

export async function getTopActors() {
  const actors = await prisma.threatActor.findMany({
    where: { deprecated: false, revoked: false },
    include: { _count: { select: { procedures: true } } },
    orderBy: { procedures: { _count: "desc" } },
    take: 10,
  });
  return actors.map((a) => ({ id: a.id, name: a.name, country: a.country, procedureCount: a._count.procedures }));
}

export async function getCountryBreakdown() {
  const results = await prisma.threatActor.groupBy({
    by: ["country"],
    _count: true,
    where: { country: { not: null }, deprecated: false, revoked: false },
    orderBy: { _count: { country: "desc" } },
  });
  return results.map((r) => ({ country: r.country!, count: r._count }));
}

export async function getIOCStats() {
  const results = await prisma.iOC.groupBy({
    by: ["type"],
    _count: true,
    orderBy: { _count: { type: "desc" } },
  });
  return { total: results.reduce((s, r) => s + r._count, 0), byType: results.map((r) => ({ type: r.type, count: r._count })) };
}

export async function getCategoryOverview() {
  const categories = await prisma.category.findMany({
    include: {
      _count: { select: { techniques: true, actors: true } },
    },
    orderBy: { name: "asc" },
  });
  return categories.map((c) => ({
    ...c,
    techniqueCount: c._count.techniques,
    actorCount: c._count.actors,
  }));
}
