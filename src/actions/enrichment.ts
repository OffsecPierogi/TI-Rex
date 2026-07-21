"use server";

import { prisma } from "@/lib/db";
import { requireRole } from "@/lib/auth";
import { analyzeSample } from "@/actions/sandbox";
import { abuseipdbLookup, shodanLookup, type AbuseIPDBReport, type ShodanReport } from "@/lib/enrichment";
import { detectIndicatorType } from "@/lib/sandbox";

export interface EnrichmentResult {
  indicator: string;
  type: string;
  vt: {
    score: number;
    verdict: string | null;
    malwareFamily: string | null;
    malicious: number;
    total: number;
  } | null;
  abuseipdb: AbuseIPDBReport | null;
  shodan: ShodanReport | null;
  errors: string[];
  linkedMalware: { id: string; name: string }[];
  linkedActors: { id: string; name: string }[];
}

export async function enrichIOC(indicator: string, iocId?: string): Promise<EnrichmentResult> {
  await requireRole("EDITOR");
  const trimmed = indicator.trim();
  const type = detectIndicatorType(trimmed);
  const errors: string[] = [];
  let vtData: EnrichmentResult["vt"] = null;
  let abuseData: AbuseIPDBReport | null = null;
  let shodanData: ShodanReport | null = null;

  // VT/HA enrichment (existing infrastructure)
  if (type === "hash" || type === "ip" || type === "domain") {
    try {
      const sandbox = await analyzeSample(trimmed, iocId);
      if (sandbox.errors.length > 0) errors.push(...sandbox.errors);
      const vtResult = sandbox.results.find((r) => r.source === "virustotal");
      if (vtResult) {
        vtData = {
          score: vtResult.score,
          verdict: vtResult.verdict,
          malwareFamily: vtResult.malwareFamily,
          malicious: vtResult.malicious,
          total: vtResult.malicious + vtResult.suspicious + vtResult.harmless + vtResult.undetected,
        };
      }
    } catch (err) {
      errors.push(`VT/HA: ${(err as Error).message}`);
    }
  }

  // AbuseIPDB (IP only)
  if (type === "ip") {
    try {
      abuseData = await abuseipdbLookup(trimmed);
    } catch (err) {
      errors.push(`AbuseIPDB: ${(err as Error).message}`);
    }
  }

  // Shodan (IP only)
  if (type === "ip") {
    try {
      shodanData = await shodanLookup(trimmed);
    } catch (err) {
      errors.push(`Shodan: ${(err as Error).message}`);
    }
  }

  // Find linked malware/actors from IOC description or existing DB relationships
  const linkedMalware: { id: string; name: string }[] = [];
  const linkedActors: { id: string; name: string }[] = [];

  if (iocId) {
    const ioc = await prisma.iOC.findUnique({
      where: { id: iocId },
      select: { description: true },
    });
    if (ioc?.description) {
      const malwareMatches = await prisma.malware.findMany({
        where: { name: { contains: ioc.description.split(" ")[0] } },
        select: { id: true, name: true },
        take: 5,
      });
      linkedMalware.push(...malwareMatches);

      if (malwareMatches.length > 0) {
        const actorLinks = await prisma.actorMalware.findMany({
          where: { malwareId: { in: malwareMatches.map((m) => m.id) } },
          include: { actor: { select: { id: true, name: true } } },
          take: 10,
        });
        linkedActors.push(...actorLinks.map((al) => ({ id: al.actor.id, name: al.actor.name })));
      }
    }
  }

  // Also check VT malware family against DB
  if (vtData?.malwareFamily) {
    const familyMatch = await prisma.malware.findMany({
      where: {
        OR: [
          { name: { contains: vtData.malwareFamily } },
          { aliases: { contains: vtData.malwareFamily } },
        ],
      },
      select: { id: true, name: true },
      take: 3,
    });
    for (const m of familyMatch) {
      if (!linkedMalware.some((lm) => lm.id === m.id)) linkedMalware.push(m);
    }
  }

  return {
    indicator: trimmed,
    type,
    vt: vtData,
    abuseipdb: abuseData,
    shodan: shodanData,
    errors,
    linkedMalware,
    linkedActors,
  };
}
