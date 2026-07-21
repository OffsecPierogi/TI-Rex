"use server";
import { prisma } from "@/lib/db";

type CoverageStatus = "covered" | "gap" | "detection-only";

const STATUS_RANK: Record<CoverageStatus, number> = { gap: 0, covered: 1, "detection-only": 2 };

export async function getPurpleTeamCoverage(opts: {
  search?: string;
  status?: CoverageStatus;
  tactic?: string;
  category?: string;
}) {
  const where: Record<string, unknown> = {
    deprecated: false,
    revoked: false,
  };

  if (opts.status === "covered") {
    where.atomicTests = { some: {} };
    where.detections = { some: {} };
  } else if (opts.status === "gap") {
    where.atomicTests = { some: {} };
    where.detections = { none: {} };
  } else if (opts.status === "detection-only") {
    where.atomicTests = { none: {} };
    where.detections = { some: {} };
  } else {
    where.OR = [{ atomicTests: { some: {} } }, { detections: { some: {} } }];
  }

  if (opts.search) {
    const searchClause = [
      { name: { contains: opts.search } },
      { externalId: { contains: opts.search } },
    ];
    if (where.OR) {
      where.AND = [{ OR: where.OR as unknown[] }, { OR: searchClause }];
      delete where.OR;
    } else {
      where.OR = searchClause;
    }
  }

  if (opts.tactic) {
    where.tactics = { some: { tactic: { shortName: opts.tactic } } };
  }

  if (opts.category) {
    where.categories = { some: { category: { slug: opts.category } } };
  }

  const techniques = await prisma.technique.findMany({
    where: where as never,
    include: {
      _count: { select: { atomicTests: true, detections: true } },
      tactics: { include: { tactic: { select: { id: true, name: true, shortName: true } } } },
      categories: { include: { category: { select: { slug: true, name: true, color: true } } } },
    },
    orderBy: { externalId: "asc" },
  });

  const classified = techniques.map((t) => {
    const hasAtomics = t._count.atomicTests > 0;
    const hasDetections = t._count.detections > 0;
    const status: CoverageStatus = hasAtomics && hasDetections ? "covered" : hasAtomics ? "gap" : "detection-only";
    return {
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      status,
      atomicCount: t._count.atomicTests,
      detectionCount: t._count.detections,
      tactics: t.tactics.map((tt) => tt.tactic),
      categories: t.categories.map((ct) => ct.category),
    };
  });

  classified.sort((a, b) => {
    const rankDiff = STATUS_RANK[a.status] - STATUS_RANK[b.status];
    if (rankDiff !== 0) return rankDiff;
    return b.atomicCount - a.atomicCount;
  });

  return classified;
}

export async function getPurpleTeamStats() {
  const [withAtomics, withDetections, both, atomicsOnly, detectionsOnly, byTactic, byCategory] =
    await Promise.all([
      prisma.technique.count({ where: { deprecated: false, revoked: false, atomicTests: { some: {} } } }),
      prisma.technique.count({ where: { deprecated: false, revoked: false, detections: { some: {} } } }),
      prisma.technique.count({
        where: { deprecated: false, revoked: false, atomicTests: { some: {} }, detections: { some: {} } },
      }),
      prisma.technique.count({
        where: { deprecated: false, revoked: false, atomicTests: { some: {} }, detections: { none: {} } },
      }),
      prisma.technique.count({
        where: { deprecated: false, revoked: false, atomicTests: { none: {} }, detections: { some: {} } },
      }),
      prisma.tactic.findMany({
        select: {
          id: true,
          name: true,
          shortName: true,
          _count: {
            select: {
              techniques: true,
            },
          },
        },
        orderBy: { orderIndex: "asc" },
      }),
      prisma.category.findMany({
        select: { slug: true, name: true, color: true, _count: { select: { techniques: true } } },
        orderBy: { name: "asc" },
      }),
    ]);

  const covered = both;
  const gaps = atomicsOnly;
  const detectionOnly = detectionsOnly;
  const coveragePct = covered + gaps > 0 ? Math.round((covered / (covered + gaps)) * 100) : 0;

  return {
    withAtomics,
    withDetections,
    covered,
    gaps,
    detectionOnly,
    coveragePct,
    byTactic: byTactic.map((t) => ({ id: t.id, name: t.name, shortName: t.shortName, techniqueCount: t._count.techniques })),
    byCategory: byCategory.map((c) => ({ slug: c.slug, name: c.name, color: c.color, techniqueCount: c._count.techniques })),
  };
}

export async function getPurpleTeamDetail(techniqueId: string) {
  const technique = await prisma.technique.findUnique({
    where: { id: techniqueId },
    include: {
      tactics: { include: { tactic: true } },
      categories: { include: { category: true } },
      atomicTests: { orderBy: { name: "asc" } },
      detections: { orderBy: [{ severity: "asc" }, { name: "asc" }] },
    },
  });

  if (!technique) return null;

  const hasAtomics = technique.atomicTests.length > 0;
  const hasDetections = technique.detections.length > 0;
  const status: CoverageStatus = hasAtomics && hasDetections ? "covered" : hasAtomics ? "gap" : "detection-only";

  let suggestedActions: string[] = [];
  if (status === "gap") {
    const executors = [...new Set(technique.atomicTests.map((t) => t.executor))];
    suggestedActions = [
      `Write detection rules covering ${executors.join(", ")} execution patterns`,
      ...technique.atomicTests.slice(0, 3).map((t) => {
        const firstLine = t.command.split("\n")[0].trim().slice(0, 80);
        return `Detect: ${firstLine}${firstLine.length >= 80 ? "..." : ""}`;
      }),
    ];
  } else if (status === "detection-only") {
    suggestedActions = [
      "Create Atomic Red Team simulations to validate these detection rules",
      "Run simulation exercises to verify rule fidelity",
    ];
  } else {
    suggestedActions = [
      `${technique.atomicTests.length} simulation(s): ${technique.atomicTests.map((t) => t.name).join("; ")}`,
      `${technique.detections.length} detection rule(s): ${technique.detections.map((d) => d.name).join("; ")}`,
    ];
  }

  return {
    ...technique,
    platforms: JSON.parse(technique.platforms) as string[],
    dataSources: technique.dataSources ? (JSON.parse(technique.dataSources) as string[]) : [],
    status,
    suggestedActions,
  };
}
