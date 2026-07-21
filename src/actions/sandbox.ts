"use server";

import { prisma } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import {
  vtLookupHash,
  vtLookupIP,
  vtLookupDomain,
  haLookupHash,
  detectIndicatorType,
  type SandboxReport,
} from "@/lib/sandbox";

export async function analyzeSample(indicator: string, iocId?: string) {
  await requireRole("EDITOR");
  const trimmed = indicator.trim();
  const type = detectIndicatorType(trimmed);
  const errors: string[] = [];

  if (type === "unknown") {
    return { results: [], errors: ["Unrecognized indicator format. Enter a hash, IP, or domain."] };
  }

  const cacheThreshold = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const cached = await prisma.sandboxAnalysis.findMany({
    where: { indicator: trimmed, fetchedAt: { gt: cacheThreshold } },
  });
  if (cached.length > 0) {
    return { results: cached, errors: [] };
  }

  const reports: SandboxReport[] = [];

  if (type === "hash") {
    const [vt, ha] = await Promise.allSettled([vtLookupHash(trimmed), haLookupHash(trimmed)]);
    if (vt.status === "fulfilled" && vt.value) reports.push(vt.value);
    else if (vt.status === "rejected") errors.push(`VirusTotal: ${vt.reason?.message ?? vt.reason}`);
    if (ha.status === "fulfilled" && ha.value) reports.push(ha.value);
    else if (ha.status === "rejected") errors.push(`Hybrid Analysis: ${ha.reason?.message ?? ha.reason}`);
  } else if (type === "ip") {
    try {
      const r = await vtLookupIP(trimmed);
      if (r) reports.push(r);
    } catch (err) {
      errors.push(`VirusTotal: ${(err as Error).message}`);
    }
  } else if (type === "domain") {
    try {
      const r = await vtLookupDomain(trimmed);
      if (r) reports.push(r);
    } catch (err) {
      errors.push(`VirusTotal: ${(err as Error).message}`);
    }
  }

  for (const report of reports) {
    try {
      const r = report as unknown as Record<string, unknown>;
      const data = {
        indicatorType: report.indicatorType,
        malicious: (r.malicious as number) ?? 0,
        suspicious: (r.suspicious as number) ?? 0,
        harmless: (r.harmless as number) ?? 0,
        undetected: (r.undetected as number) ?? 0,
        score: report.score,
        verdict: report.verdict,
        malwareFamily: (r.malwareFamily as string) ?? null,
        tags: JSON.stringify(report.tags),
        fileType: (r.fileType as string) ?? null,
        fileSize: (r.fileSize as number) ?? null,
        fileName: (r.fileName as string) ?? null,
        sha256: (r.sha256 as string) ?? null,
        md5: (r.md5 as string) ?? null,
        sha1: (r.sha1 as string) ?? null,
        ssdeep: (r.ssdeep as string) ?? null,
        firstSeen: report.firstSeen ? new Date(report.firstSeen) : null,
        lastSeen: report.lastSeen ? new Date(report.lastSeen) : null,
        techniques: JSON.stringify(report.techniques),
        rawJson: (r.rawJson as string) ?? null,
        iocId: iocId ?? undefined,
        fetchedAt: new Date(),
      };
      await prisma.sandboxAnalysis.upsert({
        where: { indicator_source: { indicator: trimmed, source: report.source } },
        update: data,
        create: { indicator: trimmed, source: report.source, ...data },
      });
    } catch (err) {
      errors.push(`Failed to cache ${report.source}: ${(err as Error).message}`);
    }
  }

  const results = await prisma.sandboxAnalysis.findMany({
    where: { indicator: trimmed },
    orderBy: { fetchedAt: "desc" },
  });

  return { results, errors };
}

export async function getAnalysisHistory(indicator: string) {
  return prisma.sandboxAnalysis.findMany({
    where: { indicator: indicator.trim() },
    orderBy: { fetchedAt: "desc" },
  });
}

export async function getAnalysisByIOC(iocId: string) {
  return prisma.sandboxAnalysis.findMany({
    where: { iocId },
    orderBy: { fetchedAt: "desc" },
  });
}

export async function getRecentAnalyses(limit = 20) {
  return prisma.sandboxAnalysis.findMany({
    select: {
      id: true,
      indicator: true,
      indicatorType: true,
      source: true,
      score: true,
      verdict: true,
      malwareFamily: true,
      fetchedAt: true,
    },
    orderBy: { fetchedAt: "desc" },
    take: limit,
  });
}
