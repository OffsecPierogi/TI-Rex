"use server";

import { prisma } from "@/lib/db";

export async function getTools(opts: { page?: number; search?: string }) {
  const page = opts.page ?? 1;
  const take = 30;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = { deprecated: false, revoked: false };
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { description: { contains: opts.search } },
      { aliases: { contains: opts.search } },
    ];
  }

  const [tools, total] = await Promise.all([
    prisma.tool.findMany({
      where: where as never,
      include: {
        _count: { select: { procedures: true } },
      },
      orderBy: { name: "asc" },
      skip,
      take,
    }),
    prisma.tool.count({ where: where as never }),
  ]);

  return {
    tools: tools.map((t) => ({
      id: t.id,
      name: t.name,
      externalId: t.externalId,
      aliases: (() => { try { const p = t.aliases ? JSON.parse(t.aliases) : null; return Array.isArray(p) ? p : []; } catch { return []; } })(),
      platforms: t.platforms ? (JSON.parse(t.platforms) as string[]) : [],
      description: t.description,
      url: t.url,
      procedureCount: t._count.procedures,
    })),
    total,
    pages: Math.ceil(total / take),
  };
}

export async function getToolDetail(id: string) {
  const tool = await prisma.tool.findUnique({
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
    },
  });

  if (!tool) return null;

  const techniqueIds = [...new Set(tool.procedures.map((p) => p.techniqueId))];
  const atomicTests =
    techniqueIds.length > 0
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

  return {
    ...tool,
    aliases: (() => { try { const p = tool.aliases ? JSON.parse(tool.aliases) : null; return Array.isArray(p) ? p : []; } catch { return []; } })(),
    platforms: tool.platforms ? (JSON.parse(tool.platforms) as string[]) : [],
    atomicTests,
  };
}

export async function getToolStats() {
  const [total, withProcedures, topTools] = await Promise.all([
    prisma.tool.count({ where: { deprecated: false, revoked: false } }),
    prisma.tool.count({
      where: {
        deprecated: false,
        revoked: false,
        procedures: { some: {} },
      },
    }),
    prisma.tool.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        name: true,
        _count: { select: { procedures: true } },
      },
      orderBy: { procedures: { _count: "desc" } },
      take: 10,
    }),
  ]);

  return {
    total,
    withProcedures,
    topTools: topTools.map((t) => ({
      name: t.name,
      count: t._count.procedures,
    })),
  };
}
