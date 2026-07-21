"use server";

import { prisma } from "@/lib/db";

export interface C2Meta {
  c2: boolean;
  c2Category: string;
  license: string;
  languages: string[];
  keyFeatures: string[];
}

function parseC2Meta(aliases: string | null): C2Meta | null {
  if (!aliases) return null;
  try {
    const parsed = JSON.parse(aliases) as Record<string, unknown>;
    if (!parsed.c2) return null;
    return parsed as unknown as C2Meta;
  } catch {
    return null;
  }
}

export async function getC2Profiles(opts: {
  search?: string;
  category?: string;
}) {
  // Fetch all tools where aliases contains '"c2":true' or '"c2": true'
  const tools = await prisma.tool.findMany({
    where: {
      OR: [
        { aliases: { contains: '"c2":true' } },
        { aliases: { contains: '"c2": true' } },
      ],
    },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              tactics: {
                include: { tactic: { select: { name: true, shortName: true } } },
              },
            },
          },
        },
      },
      _count: { select: { procedures: true } },
    },
    orderBy: { name: "asc" },
  });

  interface C2ListItem extends C2Meta {
    id: string;
    name: string;
    externalId: string;
    description: string;
    platforms: string[];
    procedureCount: number;
    techniqueCount: number;
    topTechniqueIds: string[];
  }

  const results: C2ListItem[] = tools
    .map((tool) => {
      const meta = parseC2Meta(tool.aliases);
      if (!meta) return null;

      const platforms = tool.platforms
        ? (JSON.parse(tool.platforms) as string[])
        : [];

      const item: C2ListItem = {
        id: tool.id,
        name: tool.name,
        externalId: tool.externalId,
        description: tool.description,
        platforms,
        procedureCount: tool._count.procedures,
        techniqueCount: tool.techniques.length,
        topTechniqueIds: tool.techniques
          .slice(0, 6)
          .map((t) => t.technique.externalId),
        ...meta,
      };
      return item;
    })
    .filter((x): x is C2ListItem => x !== null);

  // Apply filters
  let filtered = results;

  if (opts.search) {
    const q = opts.search.toLowerCase();
    filtered = filtered.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.description.toLowerCase().includes(q) ||
        c.languages.some((l) => l.toLowerCase().includes(q)) ||
        c.keyFeatures.some((f) => f.toLowerCase().includes(q))
    );
  }

  if (opts.category && opts.category !== "all") {
    filtered = filtered.filter((c) => c.c2Category === opts.category);
  }

  const commercialCount = results.filter(
    (c) => c.c2Category === "commercial"
  ).length;
  const openSourceCount = results.filter(
    (c) => c.c2Category === "open-source"
  ).length;

  const allTechniqueIds = new Set(
    results.flatMap((c) => c.topTechniqueIds)
  );

  return {
    c2s: filtered,
    total: results.length,
    filtered: filtered.length,
    commercialCount,
    openSourceCount,
    totalUniqueTechniques: allTechniqueIds.size,
  };
}

export async function getC2Detail(id: string) {
  const tool = await prisma.tool.findUnique({
    where: { id },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              description: true,
              _count: { select: { atomicTests: true } },
              tactics: {
                include: {
                  tactic: {
                    select: {
                      id: true,
                      name: true,
                      shortName: true,
                      externalId: true,
                    },
                  },
                },
              },
            },
          },
        },
        orderBy: { techniqueId: "asc" },
      },
      procedures: {
        include: {
          technique: {
            select: { id: true, externalId: true, name: true },
          },
        },
        take: 100,
      },
      _count: { select: { procedures: true } },
    },
  });

  if (!tool) return null;

  const meta = parseC2Meta(tool.aliases);
  if (!meta) return null;

  const platforms = tool.platforms
    ? (JSON.parse(tool.platforms) as string[])
    : [];

  // Group techniques by tactic
  const tacticMap = new Map<
    string,
    {
      tacticName: string;
      tacticShortName: string;
      tacticExternalId: string;
      techniques: Array<{
        id: string;
        externalId: string;
        name: string;
        hasTests: boolean;
      }>;
    }
  >();

  for (const tt of tool.techniques) {
    const t = tt.technique;
    const primaryTactic = t.tactics[0];
    if (!primaryTactic) continue;

    const key = primaryTactic.tactic.shortName;
    if (!tacticMap.has(key)) {
      tacticMap.set(key, {
        tacticName: primaryTactic.tactic.name,
        tacticShortName: primaryTactic.tactic.shortName,
        tacticExternalId: primaryTactic.tactic.externalId,
        techniques: [],
      });
    }
    tacticMap.get(key)!.techniques.push({
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      hasTests: t._count.atomicTests > 0,
    });
  }

  const tacticBreakdown = [...tacticMap.values()].sort((a, b) =>
    a.tacticName.localeCompare(b.tacticName)
  );

  return {
    id: tool.id,
    name: tool.name,
    externalId: tool.externalId,
    description: tool.description,
    url: tool.url,
    platforms,
    procedureCount: tool._count.procedures,
    techniqueCount: tool.techniques.length,
    tacticBreakdown,
    procedures: tool.procedures,
    ...meta,
  };
}

export async function getC2ComparisonData() {
  const tools = await prisma.tool.findMany({
    where: {
      OR: [
        { aliases: { contains: '"c2":true' } },
        { aliases: { contains: '"c2": true' } },
      ],
    },
    include: {
      techniques: {
        include: {
          technique: { select: { externalId: true, name: true } },
        },
      },
    },
    orderBy: { name: "asc" },
  });

  return tools
    .map((tool) => {
      const meta = parseC2Meta(tool.aliases);
      if (!meta) return null;
      return {
        id: tool.id,
        name: tool.name,
        c2Category: meta.c2Category,
        techniqueIds: tool.techniques.map((t) => t.technique.externalId),
      };
    })
    .filter(Boolean);
}
