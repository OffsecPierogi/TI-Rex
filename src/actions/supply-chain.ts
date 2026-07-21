"use server";

import { prisma } from "@/lib/db";

export async function getSupplyChainAlerts(opts: {
  page?: number;
  ecosystem?: string;
  severity?: string;
  search?: string;
}) {
  const page = opts.page ?? 1;
  const take = 25;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.ecosystem) where.ecosystem = opts.ecosystem;
  if (opts.severity) where.severity = opts.severity;
  if (opts.search) {
    where.OR = [
      { packageName: { contains: opts.search, mode: "insensitive" } },
      { summary: { contains: opts.search, mode: "insensitive" } },
    ];
  }

  const [items, total] = await Promise.all([
    prisma.supplyChainAlert.findMany({
      where: where as never,
      orderBy: { publishedAt: "desc" },
      skip,
      take,
    }),
    prisma.supplyChainAlert.count({ where: where as never }),
  ]);

  return { items, total, pages: Math.ceil(total / take) };
}

export async function getSupplyChainStats() {
  const [total, malicious, critical, byEcosystem] = await Promise.all([
    prisma.supplyChainAlert.count(),
    prisma.supplyChainAlert.count({ where: { severity: "critical" } }),
    prisma.supplyChainAlert.count({
      where: { severity: { in: ["critical", "high"] } },
    }),
    prisma.supplyChainAlert.groupBy({
      by: ["ecosystem"],
      _count: true,
      orderBy: { _count: { ecosystem: "desc" } },
    }),
  ]);

  return {
    total,
    malicious,
    criticalHigh: critical,
    ecosystems: byEcosystem.map((e) => ({
      ecosystem: e.ecosystem,
      count: e._count,
    })),
  };
}
