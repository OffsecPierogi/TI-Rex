"use server";

import { prisma } from "@/lib/db";

export async function getCommands(opts: {
  page?: number;
  search?: string;
  executor?: string;
  platform?: string;
  category?: string;
}) {
  const page = opts.page ?? 1;
  const take = 30;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { command: { contains: opts.search } },
      { description: { contains: opts.search } },
    ];
  }
  if (opts.executor) where.executor = opts.executor;
  if (opts.platform) where.platforms = { contains: opts.platform };
  if (opts.category) {
    where.technique = {
      categories: { some: { category: { slug: opts.category } } },
    };
  }

  const [tests, total] = await Promise.all([
    prisma.atomicTest.findMany({
      where: where as never,
      include: {
        technique: {
          select: {
            id: true,
            externalId: true,
            name: true,
            categories: { include: { category: { select: { slug: true, name: true, color: true } } } },
            procedures: {
              where: { actorId: { not: null } },
              select: { actor: { select: { id: true, name: true, country: true } } },
              distinct: ["actorId"],
              take: 10,
            },
          },
        },
      },
      orderBy: { name: "asc" },
      skip,
      take,
    }),
    prisma.atomicTest.count({ where: where as never }),
  ]);

  return {
    tests: tests.map((t) => ({
      ...t,
      platforms: JSON.parse(t.platforms) as string[],
      categories: t.technique.categories.map((c) => c.category),
    })),
    total,
    pages: Math.ceil(total / take),
  };
}

export async function getCommandDetail(id: string) {
  const test = await prisma.atomicTest.findUnique({
    where: { id },
    include: {
      technique: {
        include: {
          tactics: { include: { tactic: true } },
          categories: { include: { category: true } },
          detections: { take: 10 },
          procedures: {
            where: { OR: [{ actorId: { not: null } }, { malwareId: { not: null } }, { toolId: { not: null } }] },
            select: {
              description: true,
              actor: { select: { id: true, name: true, country: true } },
              malware: { select: { id: true, name: true } },
              tool: { select: { id: true, name: true } },
            },
            take: 50,
          },
        },
      },
    },
  });

  if (!test) return null;

  return {
    ...test,
    platforms: JSON.parse(test.platforms) as string[],
    inputArguments: test.inputArguments ? JSON.parse(test.inputArguments) : null,
  };
}

export async function getExecutors() {
  const results = await prisma.atomicTest.groupBy({
    by: ["executor"],
    _count: true,
    orderBy: { _count: { executor: "desc" } },
  });
  return results.map((r) => ({ name: r.executor, count: r._count }));
}

export async function getCategories() {
  return prisma.category.findMany({
    include: { _count: { select: { techniques: true } } },
    orderBy: { name: "asc" },
  });
}
