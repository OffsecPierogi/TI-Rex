"use server";

import { prisma } from "@/lib/db";
import { generateSigmaRule, sigmaToYaml } from "@/lib/sigma-generator";

function testToSigmaInput(t: {
  name: string;
  techniqueId: string;
  description: string;
  executor: string;
  command: string;
  platforms: string;
  elevationRequired: boolean;
  technique: { externalId: string };
}) {
  return {
    name: t.name,
    techniqueId: t.technique.externalId,
    description: t.description,
    executor: t.executor,
    command: t.command,
    platforms: t.platforms,
    elevationRequired: t.elevationRequired,
  };
}

export async function getAtomicTestsForSigma(opts: {
  page?: number;
  search?: string;
  executor?: string;
  platform?: string;
}) {
  const page = opts.page ?? 1;
  const take = 20;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (opts.search) {
    where.OR = [
      { name: { contains: opts.search } },
      { command: { contains: opts.search } },
      { description: { contains: opts.search } },
      { technique: { externalId: { contains: opts.search } } },
    ];
  }
  if (opts.executor) where.executor = opts.executor;
  if (opts.platform) where.platforms = { contains: opts.platform };

  const [rawTests, total, executorCounts] = await Promise.all([
    prisma.atomicTest.findMany({
      where: where as never,
      include: {
        technique: { select: { id: true, externalId: true, name: true } },
      },
      orderBy: [{ technique: { externalId: "asc" } }, { name: "asc" }],
      skip,
      take,
    }),
    prisma.atomicTest.count({ where: where as never }),
    prisma.atomicTest.groupBy({
      by: ["executor"],
      _count: true,
      orderBy: { _count: { executor: "desc" } },
    }),
  ]);

  const tests = rawTests.map((t) => {
    const input = testToSigmaInput(t);
    const rule = generateSigmaRule(input);
    const yaml = sigmaToYaml(rule);
    return {
      ...t,
      platforms: JSON.parse(t.platforms) as string[],
      sigmaRule: rule,
      sigmaYaml: yaml,
    };
  });

  return {
    tests,
    total,
    pages: Math.ceil(total / take),
    executorCounts: executorCounts.map((e) => ({ name: e.executor, count: e._count })),
  };
}

export async function generateSigmaForTest(testId: string) {
  const t = await prisma.atomicTest.findUnique({
    where: { id: testId },
    include: {
      technique: {
        include: {
          tactics: { include: { tactic: { select: { id: true, name: true, shortName: true } } } },
        },
      },
    },
  });

  if (!t) return null;

  const input = testToSigmaInput(t);
  const rule = generateSigmaRule(input);
  const yaml = sigmaToYaml(rule);

  return {
    ...t,
    platforms: JSON.parse(t.platforms) as string[],
    sigmaRule: rule,
    sigmaYaml: yaml,
  };
}

export async function getSigmaStats() {
  const [total, byExecutor] = await Promise.all([
    prisma.atomicTest.count(),
    prisma.atomicTest.groupBy({
      by: ["executor"],
      _count: true,
      orderBy: { _count: { executor: "desc" } },
    }),
  ]);

  return {
    total,
    byExecutor: byExecutor.map((e) => ({ name: e.executor, count: e._count })),
  };
}

export async function bulkGenerateSigma(opts: {
  executor?: string;
  techniquePrefix?: string;
}) {
  const where: Record<string, unknown> = {};
  if (opts.executor) where.executor = opts.executor;
  if (opts.techniquePrefix) {
    where.technique = { externalId: { startsWith: opts.techniquePrefix } };
  }

  const tests = await prisma.atomicTest.findMany({
    where: where as never,
    include: {
      technique: { select: { id: true, externalId: true, name: true } },
    },
    orderBy: [{ technique: { externalId: "asc" } }, { name: "asc" }],
    take: 500,
  });

  const yamls = tests.map((t) => {
    const input = testToSigmaInput(t);
    const rule = generateSigmaRule(input);
    return sigmaToYaml(rule);
  });

  return yamls.join("\n---\n");
}
