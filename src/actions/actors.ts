"use server";

import { prisma } from "@/lib/db";

export async function getActors(opts: {
  page?: number;
  search?: string;
  category?: string;
  country?: string;
}) {
  const page = opts.page ?? 1;
  const take = 50;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = { deprecated: false, revoked: false };
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { description: { contains: opts.search } },
      { aliases: { contains: opts.search } },
    ];
  }
  if (opts.category) {
    where.categories = { some: { category: { slug: opts.category } } };
  }
  if (opts.country) {
    where.country = opts.country;
  }

  const [actors, total] = await Promise.all([
    prisma.threatActor.findMany({
      where: where as never,
      include: {
        _count: { select: { procedures: true, campaigns: true } },
        categories: { include: { category: true } },
      },
      orderBy: { name: "asc" },
      skip,
      take,
    }),
    prisma.threatActor.count({ where: where as never }),
  ]);

  return {
    actors: actors.map((a) => ({
      id: a.id,
      name: a.name,
      externalId: a.externalId,
      aliases: a.aliases ? (JSON.parse(a.aliases) as string[]) : [],
      country: a.country,
      motivations: a.motivations ? (JSON.parse(a.motivations) as string[]) : [],
      matrix: a.matrix,
      procedureCount: a._count.procedures,
      campaignCount: a._count.campaigns,
      categories: a.categories.map((c) => ({
        slug: c.category.slug,
        name: c.category.name,
        color: c.category.color,
      })),
    })),
    total,
    pages: Math.ceil(total / take),
  };
}

export async function getActorDetail(id: string) {
  const actor = await prisma.threatActor.findUnique({
    where: { id },
    include: {
      procedures: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              _count: { select: { atomicTests: true } },
            },
          },
        },
        take: 500,
      },
      campaigns: {
        include: {
          campaign: true,
        },
      },
      categories: { include: { category: true } },
      advisories: {
        include: {
          advisory: {
            select: {
              id: true,
              advisoryId: true,
              cveId: true,
              title: true,
              severity: true,
              cvssScore: true,
              epssScore: true,
              knownRansomware: true,
            },
          },
        },
      },
      feedItems: {
        include: {
          feedItem: {
            select: {
              id: true,
              title: true,
              url: true,
              source: true,
              summary: true,
              publishedAt: true,
              tags: true,
            },
          },
        },
      },
    },
  });

  if (!actor) return null;

  const techniqueIds = [...new Set(actor.procedures.map((p) => p.techniqueId))];
  const atomicTests = techniqueIds.length > 0
    ? await prisma.atomicTest.findMany({
        where: { techniqueId: { in: techniqueIds } },
        select: {
          id: true,
          name: true,
          command: true,
          executor: true,
          platforms: true,
          elevationRequired: true,
          techniqueId: true,
          technique: { select: { externalId: true, name: true } },
        },
        orderBy: { name: "asc" },
      })
    : [];

  const aptReports = actor.feedItems
    .map((fi) => fi.feedItem)
    .sort((a, b) => {
      if (a.publishedAt && b.publishedAt) return b.publishedAt.getTime() - a.publishedAt.getTime();
      if (a.publishedAt) return -1;
      if (b.publishedAt) return 1;
      return 0;
    });

  const exploitedCves = actor.advisories
    .map((aa) => aa.advisory)
    .sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));

  return {
    ...actor,
    aliases: actor.aliases ? (JSON.parse(actor.aliases) as string[]) : [],
    motivations: actor.motivations ? (JSON.parse(actor.motivations) as string[]) : [],
    atomicTests,
    aptReports,
    exploitedCves,
  };
}

export async function getCountryCounts() {
  const results = await prisma.threatActor.groupBy({
    by: ["country"],
    _count: true,
    where: { country: { not: null }, deprecated: false, revoked: false },
    orderBy: { _count: { country: "desc" } },
  });
  return results.map((r) => ({ country: r.country!, count: r._count }));
}
