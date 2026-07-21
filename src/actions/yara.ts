"use server";

import { prisma } from "@/lib/db";

export async function getYaraRules(opts: {
  page?: number;
  search?: string;
  category?: string;
  severity?: string;
  malwareId?: string;
}) {
  const page = opts.page ?? 1;
  const take = 20;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { description: { contains: opts.search } },
      { rule: { contains: opts.search } },
      { tags: { contains: opts.search } },
    ];
  }
  if (opts.category) where.category = opts.category;
  if (opts.severity) where.severity = opts.severity;
  if (opts.malwareId) where.malwareId = opts.malwareId;

  const [rules, total] = await Promise.all([
    prisma.yaraRule.findMany({
      where: where as never,
      include: {
        malware: { select: { id: true, name: true, externalId: true } },
        technique: { select: { id: true, name: true, externalId: true } },
      },
      orderBy: [{ severity: "desc" }, { name: "asc" }],
      skip,
      take,
    }),
    prisma.yaraRule.count({ where: where as never }),
  ]);

  return { rules, total, pages: Math.ceil(total / take) };
}

export async function getYaraRuleDetail(id: string) {
  return prisma.yaraRule.findUnique({
    where: { id },
    include: {
      malware: { select: { id: true, name: true, externalId: true, description: true, type: true } },
      technique: { select: { id: true, name: true, externalId: true, description: true } },
    },
  });
}

export async function getYaraStats() {
  const [total, byCategory, bySeverity] = await Promise.all([
    prisma.yaraRule.count(),
    prisma.yaraRule.groupBy({
      by: ["category"],
      _count: true,
      orderBy: { _count: { category: "desc" } },
    }),
    prisma.yaraRule.groupBy({
      by: ["severity"],
      _count: true,
      orderBy: { _count: { severity: "desc" } },
    }),
  ]);

  return {
    total,
    byCategory: byCategory
      .filter((r) => r.category)
      .map((r) => ({ name: r.category!, count: r._count })),
    bySeverity: bySeverity.map((r) => ({ name: r.severity, count: r._count })),
  };
}

export async function getRelatedYaraRules(id: string, category: string | null, malwareId: string | null) {
  return prisma.yaraRule.findMany({
    where: {
      id: { not: id },
      OR: [
        ...(category ? [{ category }] : []),
        ...(malwareId ? [{ malwareId }] : []),
      ],
    },
    select: { id: true, name: true, category: true, severity: true, description: true },
    orderBy: { name: "asc" },
    take: 6,
  });
}

export async function exportYaraRules(opts: { category?: string; ids?: string[] }) {
  const where: Record<string, unknown> = {};
  if (opts.category) where.category = opts.category;
  if (opts.ids && opts.ids.length > 0) where.id = { in: opts.ids };

  const rules = await prisma.yaraRule.findMany({
    where: where as never,
    orderBy: [{ category: "asc" }, { name: "asc" }],
  });

  const header = [
    "/*",
    " * TI-Rex — YARA Rule Library",
    ` * Generated: ${new Date().toISOString()}`,
    ` * Rules: ${rules.length}`,
    " * Open-source threat intelligence platform",
    " */",
    "",
  ].join("\n");

  const body = rules.map((r) => r.rule).join("\n\n");
  return header + body + "\n";
}
