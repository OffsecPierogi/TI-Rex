"use server";

import { prisma } from "@/lib/db";

const CVE_BASE_WHERE = { cveId: { not: null } };

export async function getCves(opts: {
  page?: number;
  search?: string;
  vendor?: string;
  ransomware?: boolean;
  aptLinked?: boolean;
  days?: number;
  sortBy?: "epss" | "cvss" | "date";
  minEpss?: number;
  source?: "all" | "kev" | "nvd";
}) {
  const page = opts.page ?? 1;
  const take = 20;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = { ...CVE_BASE_WHERE };
  if (opts.search) {
    where.OR = [
      { title: { contains: opts.search, mode: "insensitive" } },
      { cveId: { contains: opts.search, mode: "insensitive" } },
      { description: { contains: opts.search, mode: "insensitive" } },
    ];
  }
  if (opts.vendor) where.vendorProject = { equals: opts.vendor, mode: "insensitive" };
  if (opts.ransomware) where.knownRansomware = true;
  if (opts.aptLinked) where.actors = { some: {} };
  if (opts.source === "kev") where.type = "kev";
  else if (opts.source === "nvd") where.type = "NVD";
  const daysFilter = opts.days ?? 30;
  if (daysFilter > 0) {
    const cutoff = new Date(Date.now() - daysFilter * 86400000);
    where.AND = [
      ...(Array.isArray(where.AND) ? where.AND : []),
      {
        OR: [
          { dateAdded: { gte: cutoff } },
          { publishedDate: { gte: cutoff } },
        ],
      },
    ];
  }
  if (opts.minEpss !== undefined && opts.minEpss > 0) {
    where.epssScore = { gte: opts.minEpss };
  }

  let orderBy: Record<string, string>;
  switch (opts.sortBy) {
    case "epss":
      orderBy = { epssScore: "desc" };
      break;
    case "cvss":
      orderBy = { cvssScore: "desc" };
      break;
    default:
      orderBy = { publishedDate: "desc" };
      break;
  }

  const [items, total] = await Promise.all([
    prisma.advisory.findMany({
      where: where as never,
      orderBy: orderBy as never,
      skip,
      take,
      include: {
        actors: {
          include: {
            actor: { select: { id: true, name: true, country: true } },
          },
        },
      },
    }),
    prisma.advisory.count({ where: where as never }),
  ]);

  return { items, total, pages: Math.ceil(total / take) };
}

export async function getCveStats() {
  const now = Date.now();
  const base = CVE_BASE_WHERE;

  const [total, kevCount, ransomwareLinked, aptLinked, last30d, last90d, byVendor, highEpss, epssAgg] = await Promise.all([
    prisma.advisory.count({ where: base as never }),
    prisma.advisory.count({ where: { ...base, type: "kev" } as never }),
    prisma.advisory.count({ where: { ...base, knownRansomware: true } as never }),
    prisma.advisory.count({ where: { ...base, actors: { some: {} } } as never }),
    prisma.advisory.count({
      where: {
        ...base,
        OR: [
          { dateAdded: { gte: new Date(now - 30 * 86400000) } },
          { publishedDate: { gte: new Date(now - 30 * 86400000) } },
        ],
      } as never,
    }),
    prisma.advisory.count({
      where: {
        ...base,
        OR: [
          { dateAdded: { gte: new Date(now - 90 * 86400000) } },
          { publishedDate: { gte: new Date(now - 90 * 86400000) } },
        ],
      } as never,
    }),
    prisma.advisory.groupBy({
      by: ["vendorProject"],
      where: { ...base, vendorProject: { not: null } } as never,
      _count: true,
      orderBy: { _count: { vendorProject: "desc" } },
      take: 10,
    }),
    prisma.advisory.count({
      where: { ...base, epssScore: { gt: 0.5 } } as never,
    }),
    prisma.advisory.aggregate({
      where: { ...base, epssScore: { not: null } } as never,
      _avg: { epssScore: true },
    }),
  ]);

  return {
    total,
    kevCount,
    ransomwareLinked,
    aptLinked,
    last30d,
    last90d,
    topVendors: byVendor.map((v) => ({ vendor: v.vendorProject as string, count: v._count })),
    highEpss,
    avgEpss: epssAgg._avg.epssScore ?? 0,
  };
}

export async function getCveDetail(id: string) {
  return prisma.advisory.findUnique({
    where: { id },
    include: {
      iocs: true,
      actors: {
        include: {
          actor: {
            select: { id: true, name: true, country: true },
          },
        },
      },
    },
  });
}
