"use server";

import { prisma } from "@/lib/db";

export async function getDetections(opts: {
  page?: number;
  search?: string;
  language?: string;
  category?: string;
  severity?: string;
}) {
  const page = opts.page ?? 1;
  const take = 30;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { query: { contains: opts.search } },
      { description: { contains: opts.search } },
    ];
  }
  if (opts.language) where.language = opts.language;
  if (opts.category) where.category = opts.category;
  if (opts.severity) where.severity = opts.severity;

  const [rules, total] = await Promise.all([
    prisma.detectionRule.findMany({
      where: where as never,
      include: {
        technique: { select: { id: true, externalId: true, name: true } },
      },
      orderBy: { name: "asc" },
      skip,
      take,
    }),
    prisma.detectionRule.count({ where: where as never }),
  ]);

  return { rules, total, pages: Math.ceil(total / take) };
}

export async function getDetectionStats() {
  const [byLanguage, byCategory, bySeverity, total] = await Promise.all([
    prisma.detectionRule.groupBy({
      by: ["language"],
      _count: true,
      orderBy: { _count: { language: "desc" } },
    }),
    prisma.detectionRule.groupBy({
      by: ["category"],
      _count: true,
      orderBy: { _count: { category: "desc" } },
    }),
    prisma.detectionRule.groupBy({
      by: ["severity"],
      _count: true,
      orderBy: { _count: { severity: "desc" } },
    }),
    prisma.detectionRule.count(),
  ]);

  return {
    total,
    byLanguage: byLanguage.map((r) => ({ name: r.language, count: r._count })),
    byCategory: byCategory.map((r) => ({ name: r.category, count: r._count })),
    bySeverity: bySeverity.map((r) => ({ name: r.severity, count: r._count })),
  };
}
