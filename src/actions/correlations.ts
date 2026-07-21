"use server";

import { prisma } from "@/lib/db";

export interface CorrelationHit {
  value: string;
  type: string;
  sources: { source: string; description: string | null; firstSeen: string | null }[];
  sourceCount: number;
  malwareLinks: { id: string; name: string; type: string | null }[];
  actorLinks: { id: string; name: string; country: string | null }[];
  advisoryLinks: { id: string; advisoryId: string; title: string }[];
}

export interface CorrelationStats {
  totalIOCs: number;
  multiSourceHits: number;
  sourceCounts: { source: string; count: number }[];
  topMalware: { name: string; iocCount: number }[];
}

export async function getCorrelations(opts?: {
  page?: number;
  minSources?: number;
  type?: string;
  search?: string;
}): Promise<{ hits: CorrelationHit[]; total: number; pages: number }> {
  const page = opts?.page ?? 1;
  const take = 30;
  const minSources = opts?.minSources ?? 2;

  const where: Record<string, unknown> = {};
  if (opts?.type) where.type = opts.type;
  if (opts?.search) {
    where.OR = [
      { value: { contains: opts.search } },
      { description: { contains: opts.search } },
    ];
  }

  const allIOCs = await prisma.iOC.findMany({
    where: where as never,
    select: {
      id: true,
      type: true,
      value: true,
      source: true,
      description: true,
      firstSeen: true,
      advisoryId: true,
      advisory: { select: { id: true, advisoryId: true, title: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  const grouped = new Map<string, typeof allIOCs>();
  for (const ioc of allIOCs) {
    const key = `${ioc.type}:${ioc.value}`;
    const existing = grouped.get(key);
    if (existing) {
      existing.push(ioc);
    } else {
      grouped.set(key, [ioc]);
    }
  }

  const multiSource = [...grouped.entries()]
    .filter(([, iocs]) => {
      const uniqueSources = new Set(iocs.map((i) => i.source));
      return uniqueSources.size >= minSources;
    })
    .sort((a, b) => {
      const aUnique = new Set(a[1].map((i) => i.source)).size;
      const bUnique = new Set(b[1].map((i) => i.source)).size;
      return bUnique - aUnique;
    });

  const total = multiSource.length;
  const pages = Math.ceil(total / take);
  const paged = multiSource.slice((page - 1) * take, page * take);

  const allDescriptions = paged.flatMap(([, iocs]) =>
    iocs.map((i) => i.description).filter(Boolean) as string[]
  );

  const malwareLookup = new Map<string, { id: string; name: string; type: string | null }>();
  const malwareIdToActors = new Map<string, { id: string; name: string; country: string | null }[]>();

  if (allDescriptions.length > 0) {
    const malwareKeywords = new Set<string>();
    for (const desc of allDescriptions) {
      for (const word of desc.split(/[\s,;:|/()]+/)) {
        if (word.length > 3) malwareKeywords.add(word);
      }
    }

    const keywordArray = [...malwareKeywords].slice(0, 50);
    if (keywordArray.length > 0) {
      const malwareMatches = await prisma.malware.findMany({
        where: { OR: keywordArray.map((kw) => ({ name: { contains: kw } })) },
        select: { id: true, name: true, type: true },
        take: 100,
      });
      for (const m of malwareMatches) malwareLookup.set(m.name.toLowerCase(), m);

      if (malwareMatches.length > 0) {
        const actorMalwareLinks = await prisma.actorMalware.findMany({
          where: { malwareId: { in: malwareMatches.map((m) => m.id) } },
          include: { actor: { select: { id: true, name: true, country: true } } },
        });
        for (const al of actorMalwareLinks) {
          const existing = malwareIdToActors.get(al.malwareId);
          if (existing) {
            if (!existing.some((a) => a.id === al.actor.id)) existing.push(al.actor);
          } else {
            malwareIdToActors.set(al.malwareId, [al.actor]);
          }
        }
      }
    }
  }

  const hits: CorrelationHit[] = paged.map(([, iocs]) => {
    const first = iocs[0];
    const uniqueSources = new Map<string, typeof iocs[0]>();
    for (const ioc of iocs) {
      if (!uniqueSources.has(ioc.source)) uniqueSources.set(ioc.source, ioc);
    }

    const malwareLinks: CorrelationHit["malwareLinks"] = [];
    const actorLinks: CorrelationHit["actorLinks"] = [];
    const advisoryLinks: CorrelationHit["advisoryLinks"] = [];

    for (const ioc of iocs) {
      if (ioc.description) {
        for (const [name, m] of malwareLookup) {
          if (ioc.description.toLowerCase().includes(name)) {
            if (!malwareLinks.some((ml) => ml.id === m.id)) malwareLinks.push(m);
          }
        }
      }
      if (ioc.advisory && !advisoryLinks.some((a) => a.id === ioc.advisory!.id)) {
        advisoryLinks.push(ioc.advisory);
      }
    }

    for (const ml of malwareLinks) {
      const actors = malwareIdToActors.get(ml.id);
      if (actors) {
        for (const actor of actors) {
          if (!actorLinks.some((a) => a.id === actor.id)) actorLinks.push(actor);
        }
      }
    }

    return {
      value: first.value,
      type: first.type,
      sources: [...uniqueSources.values()].map((s) => ({
        source: s.source,
        description: s.description,
        firstSeen: s.firstSeen?.toISOString() ?? null,
      })),
      sourceCount: uniqueSources.size,
      malwareLinks,
      actorLinks,
      advisoryLinks,
    };
  });

  return { hits, total, pages };
}

export async function getCorrelationStats(): Promise<CorrelationStats> {
  const [totalIOCs, sourceCounts] = await Promise.all([
    prisma.iOC.count(),
    prisma.iOC.groupBy({
      by: ["source"],
      _count: true,
      orderBy: { _count: { source: "desc" } },
    }),
  ]);

  const allIOCs = await prisma.iOC.findMany({
    select: { type: true, value: true, source: true },
  });

  const grouped = new Map<string, Set<string>>();
  for (const ioc of allIOCs) {
    const key = `${ioc.type}:${ioc.value}`;
    const existing = grouped.get(key);
    if (existing) {
      existing.add(ioc.source);
    } else {
      grouped.set(key, new Set([ioc.source]));
    }
  }
  const multiSourceHits = [...grouped.values()].filter((s) => s.size >= 2).length;

  const malwareDescs = await prisma.iOC.findMany({
    where: { description: { not: null } },
    select: { description: true },
    take: 500,
  });

  const malwareCounts = new Map<string, number>();
  const allMalware = await prisma.malware.findMany({
    select: { name: true },
    take: 200,
  });
  for (const m of allMalware) {
    let count = 0;
    for (const d of malwareDescs) {
      if (d.description && d.description.toLowerCase().includes(m.name.toLowerCase())) count++;
    }
    if (count > 0) malwareCounts.set(m.name, count);
  }

  const topMalware = [...malwareCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name, iocCount]) => ({ name, iocCount }));

  return {
    totalIOCs,
    multiSourceHits,
    sourceCounts: sourceCounts.map((s) => ({ source: s.source, count: s._count })),
    topMalware,
  };
}
