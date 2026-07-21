"use server";

import { prisma } from "@/lib/db";

export async function getAdvisories(opts: {
  page?: number;
  search?: string;
  ransomware?: boolean;
}) {
  const page = opts.page ?? 1;
  const take = 50;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.search) {
    where.OR = [
      { title: { contains: opts.search } },
      { cveId: { contains: opts.search } },
      { vendorProject: { contains: opts.search } },
      { product: { contains: opts.search } },
    ];
  }
  if (opts.ransomware) where.knownRansomware = true;

  const [advisories, total] = await Promise.all([
    prisma.advisory.findMany({
      where: where as never,
      orderBy: { dateAdded: "desc" },
      skip,
      take,
    }),
    prisma.advisory.count({ where: where as never }),
  ]);

  return { advisories, total, pages: Math.ceil(total / take) };
}

export async function getAdvisoryDetail(id: string) {
  return prisma.advisory.findUnique({
    where: { id },
    include: { iocs: true },
  });
}
