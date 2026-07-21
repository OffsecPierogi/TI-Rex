"use server";

import { prisma } from "@/lib/db";

export async function getTechniques(opts: {
  page?: number;
  search?: string;
  matrix?: string;
  category?: string;
}) {
  const page = opts.page ?? 1;
  const take = 50;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = { deprecated: false, revoked: false };
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { externalId: { contains: opts.search } },
      { description: { contains: opts.search } },
    ];
  }
  if (opts.matrix) where.matrix = opts.matrix;
  if (opts.category) {
    where.categories = { some: { category: { slug: opts.category } } };
  }

  const [techniques, total] = await Promise.all([
    prisma.technique.findMany({
      where: where as never,
      include: {
        parent: { select: { name: true, externalId: true } },
        _count: { select: { procedures: true, atomicTests: true, children: true } },
        categories: { include: { category: true } },
      },
      orderBy: { externalId: "asc" },
      skip,
      take,
    }),
    prisma.technique.count({ where: where as never }),
  ]);

  return {
    techniques: techniques.map((t) => ({
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      isSubtechnique: t.isSubtechnique,
      parentName: t.parent?.name ?? null,
      parentExtId: t.parent?.externalId ?? null,
      platforms: JSON.parse(t.platforms) as string[],
      matrix: t.matrix,
      procedureCount: t._count.procedures,
      atomicTestCount: t._count.atomicTests,
      childCount: t._count.children,
      categories: t.categories.map((c) => ({
        slug: c.category.slug,
        name: c.category.name,
        color: c.category.color,
      })),
    })),
    total,
    pages: Math.ceil(total / take),
  };
}

export async function getTechniqueDetail(id: string) {
  const technique = await prisma.technique.findUnique({
    where: { id },
    include: {
      parent: { select: { id: true, name: true, externalId: true } },
      children: {
        where: { deprecated: false, revoked: false },
        select: { id: true, externalId: true, name: true },
        orderBy: { externalId: "asc" },
      },
      tactics: { include: { tactic: true } },
      procedures: {
        include: {
          actor: { select: { id: true, name: true } },
          malware: { select: { id: true, name: true } },
          tool: { select: { id: true, name: true } },
          campaign: { select: { id: true, name: true } },
        },
        take: 100,
      },
      atomicTests: { orderBy: { name: "asc" } },
      categories: { include: { category: true } },
      detections: { orderBy: { severity: "asc" } },
    },
  });

  if (!technique) return null;

  return {
    ...technique,
    platforms: JSON.parse(technique.platforms) as string[],
    dataSources: technique.dataSources ? (JSON.parse(technique.dataSources) as string[]) : [],
  };
}
