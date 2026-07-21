"use server";

import { prisma } from "@/lib/db";

export async function getFeedItems(opts: {
  page?: number;
  source?: string;
  search?: string;
  days?: number;
}) {
  const page = opts.page ?? 1;
  const take = 30;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.source) where.source = opts.source;
  if (opts.search) {
    where.OR = [
      { title: { contains: opts.search } },
      { summary: { contains: opts.search } },
    ];
  }
  if (opts.days) {
    where.publishedAt = { gte: new Date(Date.now() - opts.days * 86400000) };
  }

  const [items, total] = await Promise.all([
    prisma.feedItem.findMany({
      where: where as never,
      orderBy: { publishedAt: "desc" },
      skip,
      take,
    }),
    prisma.feedItem.count({ where: where as never }),
  ]);

  return {
    items: items.map((i) => ({
      ...i,
      tags: i.tags ? (JSON.parse(i.tags) as string[]) : [],
    })),
    total,
    pages: Math.ceil(total / take),
  };
}

export async function getFeedStats() {
  const now = Date.now();
  const [total, last24h, last7d, bySrc] = await Promise.all([
    prisma.feedItem.count(),
    prisma.feedItem.count({ where: { publishedAt: { gte: new Date(now - 86400000) } } }),
    prisma.feedItem.count({ where: { publishedAt: { gte: new Date(now - 7 * 86400000) } } }),
    prisma.feedItem.groupBy({ by: ["source"], _count: true, orderBy: { _count: { source: "desc" } } }),
  ]);

  const latest = await prisma.feedItem.findFirst({ orderBy: { fetchedAt: "desc" }, select: { fetchedAt: true } });

  return {
    total,
    last24h,
    last7d,
    bySource: bySrc.map((s) => ({ source: s.source, count: s._count })),
    lastFetched: latest?.fetchedAt ?? null,
  };
}
