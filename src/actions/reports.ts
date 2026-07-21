"use server";
import { prisma } from "@/lib/db";

export type ReportType = "actor" | "malware" | "technique" | "category";

export async function generateActorReport(actorId: string) {
  const actor = await prisma.threatActor.findUnique({
    where: { id: actorId },
    include: {
      procedures: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              _count: { select: { atomicTests: true, detections: true } },
              tactics: { include: { tactic: { select: { name: true, shortName: true } } } },
            },
          },
        },
        take: 500,
      },
      campaigns: { include: { campaign: true } },
      categories: { include: { category: true } },
      malwareLinks: {
        include: {
          malware: { select: { id: true, name: true, externalId: true, type: true } },
        },
      },
    },
  });

  if (!actor) return null;

  const techniqueIds = [...new Set(actor.procedures.map((p) => p.techniqueId))];

  const [atomicTests, detectionRules] = await Promise.all([
    techniqueIds.length > 0
      ? prisma.atomicTest.findMany({
          where: { techniqueId: { in: techniqueIds } },
          select: {
            id: true,
            name: true,
            executor: true,
            platforms: true,
            elevationRequired: true,
            techniqueId: true,
            technique: { select: { externalId: true, name: true } },
          },
          orderBy: { name: "asc" },
        })
      : [],
    techniqueIds.length > 0
      ? prisma.detectionRule.findMany({
          where: { techniqueId: { in: techniqueIds } },
          select: {
            id: true,
            name: true,
            language: true,
            severity: true,
            techniqueId: true,
            technique: { select: { externalId: true, name: true } },
          },
        })
      : [],
  ]);

  const techniqueMap = new Map<string, { id: string; externalId: string; name: string; count: number; tactics: string[]; hasTests: boolean; hasDetections: boolean }>();
  for (const p of actor.procedures) {
    const existing = techniqueMap.get(p.technique.id);
    if (existing) {
      existing.count++;
    } else {
      techniqueMap.set(p.technique.id, {
        id: p.technique.id,
        externalId: p.technique.externalId,
        name: p.technique.name,
        count: 1,
        tactics: p.technique.tactics.map((tt) => tt.tactic.name),
        hasTests: p.technique._count.atomicTests > 0,
        hasDetections: p.technique._count.detections > 0,
      });
    }
  }

  const techniques = [...techniqueMap.values()].sort((a, b) => b.count - a.count);
  const techniquesWithTests = techniques.filter((t) => t.hasTests).length;
  const techniquesWithDetections = techniques.filter((t) => t.hasDetections).length;

  const malwareIds = actor.malwareLinks.map((l) => l.malware.id);
  const malwareNames = actor.malwareLinks.map((l) => l.malware.name);

  const [yaraRules, relatedIOCs] = await Promise.all([
    malwareIds.length > 0
      ? prisma.yaraRule.findMany({
          where: { malwareId: { in: malwareIds } },
          select: { id: true, name: true, category: true, severity: true, malware: { select: { name: true } } },
          take: 50,
        })
      : [],
    malwareNames.length > 0
      ? prisma.iOC.findMany({
          where: { OR: malwareNames.map((n) => ({ description: { contains: n } })) },
          select: { id: true, type: true, value: true, source: true, description: true, firstSeen: true },
          take: 50,
          orderBy: { createdAt: "desc" },
        })
      : [],
  ]);

  const aliases = actor.aliases ? (JSON.parse(actor.aliases) as string[]) : [];
  const motivations = actor.motivations ? (JSON.parse(actor.motivations) as string[]) : [];
  const tacticsUsed = [...new Set(techniques.flatMap((t) => t.tactics))];

  const executiveSummary = buildActorExecutiveSummary({
    name: actor.name,
    aliases,
    country: actor.country,
    motivations,
    techniqueCount: techniques.length,
    malwareCount: malwareIds.length,
    campaignCount: actor.campaigns.length,
    tacticsUsed,
    detectionCoverage: techniques.length > 0 ? Math.round((techniquesWithDetections / techniques.length) * 100) : 0,
  });

  const mitigations = buildMitigations(tacticsUsed, techniques.map((t) => t.externalId));

  return {
    reportType: "actor" as const,
    generatedAt: new Date().toISOString(),
    executiveSummary,
    mitigations,
    yaraRules,
    relatedIOCs: relatedIOCs.map((i) => ({ ...i, firstSeen: i.firstSeen?.toISOString() ?? null })),
    actor: {
      id: actor.id,
      externalId: actor.externalId,
      name: actor.name,
      aliases,
      country: actor.country,
      description: actor.description,
      motivations,
      url: actor.url,
      categories: actor.categories.map((c) => ({ slug: c.category.slug, name: c.category.name, color: c.category.color })),
    },
    techniques,
    malware: actor.malwareLinks.map((l) => l.malware),
    campaigns: actor.campaigns.map((ca) => ({
      id: ca.campaign.id,
      name: ca.campaign.name,
      description: ca.campaign.description,
      firstSeen: ca.campaign.firstSeen?.toISOString() ?? null,
      lastSeen: ca.campaign.lastSeen?.toISOString() ?? null,
    })),
    atomicTests: atomicTests.map((t) => ({
      ...t,
      platforms: JSON.parse(t.platforms) as string[],
    })),
    detectionRules,
    coverage: {
      totalTechniques: techniques.length,
      techniquesWithTests,
      techniquesWithDetections,
      detectionCoverage: techniques.length > 0 ? Math.round((techniquesWithDetections / techniques.length) * 100) : 0,
      testCoverage: techniques.length > 0 ? Math.round((techniquesWithTests / techniques.length) * 100) : 0,
    },
  };
}

export async function generateMalwareReport(malwareId: string) {
  const malware = await prisma.malware.findUnique({
    where: { id: malwareId },
    include: {
      procedures: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              _count: { select: { atomicTests: true, detections: true } },
              tactics: { include: { tactic: { select: { name: true } } } },
            },
          },
        },
        take: 500,
      },
      actorLinks: {
        include: {
          actor: { select: { id: true, name: true, externalId: true, country: true } },
        },
      },
    },
  });

  if (!malware) return null;

  const techniqueIds = [...new Set(malware.procedures.map((p) => p.techniqueId))];

  const [atomicTests, detectionRules] = await Promise.all([
    techniqueIds.length > 0
      ? prisma.atomicTest.findMany({
          where: { techniqueId: { in: techniqueIds } },
          select: {
            id: true,
            name: true,
            executor: true,
            platforms: true,
            elevationRequired: true,
            techniqueId: true,
            technique: { select: { externalId: true, name: true } },
          },
          orderBy: { name: "asc" },
        })
      : [],
    techniqueIds.length > 0
      ? prisma.detectionRule.findMany({
          where: { techniqueId: { in: techniqueIds } },
          select: {
            id: true,
            name: true,
            language: true,
            severity: true,
            techniqueId: true,
            technique: { select: { externalId: true, name: true } },
          },
        })
      : [],
  ]);

  const techniqueMap = new Map<string, { id: string; externalId: string; name: string; tactics: string[]; hasTests: boolean; hasDetections: boolean }>();
  for (const p of malware.procedures) {
    if (!techniqueMap.has(p.technique.id)) {
      techniqueMap.set(p.technique.id, {
        id: p.technique.id,
        externalId: p.technique.externalId,
        name: p.technique.name,
        tactics: p.technique.tactics.map((tt) => tt.tactic.name),
        hasTests: p.technique._count.atomicTests > 0,
        hasDetections: p.technique._count.detections > 0,
      });
    }
  }

  const techniques = [...techniqueMap.values()];
  const techniquesWithTests = techniques.filter((t) => t.hasTests).length;
  const techniquesWithDetections = techniques.filter((t) => t.hasDetections).length;

  const [yaraRules, relatedIOCs] = await Promise.all([
    prisma.yaraRule.findMany({
      where: { malwareId: malware.id },
      select: { id: true, name: true, category: true, severity: true },
      take: 50,
    }),
    prisma.iOC.findMany({
      where: { description: { contains: malware.name } },
      select: { id: true, type: true, value: true, source: true, description: true, firstSeen: true },
      take: 50,
      orderBy: { createdAt: "desc" },
    }),
  ]);

  const aliases = malware.aliases ? (JSON.parse(malware.aliases) as string[]) : [];
  const tacticsUsed = [...new Set(techniques.flatMap((t) => t.tactics))];
  const actorCountries = malware.actorLinks.map((l) => l.actor.country).filter(Boolean);

  const executiveSummary = buildMalwareExecutiveSummary({
    name: malware.name,
    type: malware.type,
    aliases,
    actorCount: malware.actorLinks.length,
    actorCountries: [...new Set(actorCountries)] as string[],
    techniqueCount: techniques.length,
    tacticsUsed,
    iocCount: relatedIOCs.length,
  });

  const mitigations = buildMitigations(tacticsUsed, techniques.map((t) => t.externalId));

  return {
    reportType: "malware" as const,
    generatedAt: new Date().toISOString(),
    executiveSummary,
    mitigations,
    yaraRules,
    relatedIOCs: relatedIOCs.map((i) => ({ ...i, firstSeen: i.firstSeen?.toISOString() ?? null })),
    malware: {
      id: malware.id,
      externalId: malware.externalId,
      name: malware.name,
      aliases,
      description: malware.description,
      type: malware.type,
      platforms: malware.platforms ? (JSON.parse(malware.platforms) as string[]) : [],
      url: malware.url,
    },
    techniques,
    actors: malware.actorLinks.map((l) => l.actor),
    atomicTests: atomicTests.map((t) => ({
      ...t,
      platforms: JSON.parse(t.platforms) as string[],
    })),
    detectionRules,
    coverage: {
      totalTechniques: techniques.length,
      techniquesWithTests,
      techniquesWithDetections,
      detectionCoverage: techniques.length > 0 ? Math.round((techniquesWithDetections / techniques.length) * 100) : 0,
      testCoverage: techniques.length > 0 ? Math.round((techniquesWithTests / techniques.length) * 100) : 0,
    },
  };
}

export async function generateTechniqueReport(techniqueId: string) {
  const technique = await prisma.technique.findUnique({
    where: { id: techniqueId },
    include: {
      parent: { select: { id: true, externalId: true, name: true } },
      children: {
        where: { deprecated: false, revoked: false },
        select: { id: true, externalId: true, name: true },
        orderBy: { externalId: "asc" },
      },
      tactics: { include: { tactic: true } },
      procedures: {
        include: {
          actor: { select: { id: true, name: true } },
          malware: { select: { id: true, name: true } },
          tool: { select: { id: true, name: true } },
          campaign: { select: { id: true, name: true } },
        },
        take: 100,
      },
      atomicTests: { orderBy: { name: "asc" } },
      categories: { include: { category: true } },
      detections: { orderBy: { severity: "asc" } },
    },
  });

  if (!technique) return null;

  return {
    reportType: "technique" as const,
    generatedAt: new Date().toISOString(),
    technique: {
      id: technique.id,
      externalId: technique.externalId,
      name: technique.name,
      description: technique.description,
      platforms: JSON.parse(technique.platforms) as string[],
      dataSources: technique.dataSources ? (JSON.parse(technique.dataSources) as string[]) : [],
      detection: technique.detection,
      isSubtechnique: technique.isSubtechnique,
      url: technique.url,
      parent: technique.parent,
      children: technique.children,
      tactics: technique.tactics.map((tt) => ({ id: tt.tactic.id, name: tt.tactic.name, shortName: tt.tactic.shortName })),
      categories: technique.categories.map((ct) => ({ slug: ct.category.slug, name: ct.category.name, color: ct.category.color })),
    },
    procedures: technique.procedures,
    atomicTests: technique.atomicTests.map((t) => ({
      ...t,
      platforms: JSON.parse(t.platforms) as string[],
    })),
    detectionRules: technique.detections,
    coverage: {
      procedureCount: technique.procedures.length,
      atomicTestCount: technique.atomicTests.length,
      detectionRuleCount: technique.detections.length,
    },
  };
}

export async function generateCategoryReport(categorySlug: string) {
  const category = await prisma.category.findUnique({
    where: { slug: categorySlug },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              isSubtechnique: true,
              _count: { select: { procedures: true, atomicTests: true, detections: true } },
            },
          },
        },
      },
      actors: {
        include: {
          actor: {
            select: {
              id: true,
              externalId: true,
              name: true,
              country: true,
              _count: { select: { procedures: true } },
            },
          },
        },
      },
    },
  });

  if (!category) return null;

  const techniques = category.techniques
    .map((ct) => ct.technique)
    .sort((a, b) => a.externalId.localeCompare(b.externalId));

  const actors = category.actors
    .map((ca) => ca.actor)
    .sort((a, b) => b._count.procedures - a._count.procedures);

  const techniquesWithTests = techniques.filter((t) => t._count.atomicTests > 0).length;
  const techniquesWithDetections = techniques.filter((t) => t._count.detections > 0).length;
  const total = techniques.length;

  return {
    reportType: "category" as const,
    generatedAt: new Date().toISOString(),
    category: {
      id: category.id,
      slug: category.slug,
      name: category.name,
      description: category.description,
      color: category.color,
    },
    techniques: techniques.map((t) => ({
      id: t.id,
      externalId: t.externalId,
      name: t.name,
      isSubtechnique: t.isSubtechnique,
      procedureCount: t._count.procedures,
      atomicTestCount: t._count.atomicTests,
      detectionCount: t._count.detections,
    })),
    actors: actors.map((a) => ({
      id: a.id,
      externalId: a.externalId,
      name: a.name,
      country: a.country,
      procedureCount: a._count.procedures,
    })),
    coverage: {
      totalTechniques: total,
      techniquesWithTests,
      techniquesWithDetections,
      techniquesWithoutDetections: total - techniquesWithDetections,
      detectionCoverage: total > 0 ? Math.round((techniquesWithDetections / total) * 100) : 0,
      testCoverage: total > 0 ? Math.round((techniquesWithTests / total) * 100) : 0,
    },
  };
}

export async function getReportableEntities() {
  const [actors, malware, techniques, categories] = await Promise.all([
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        id: true,
        name: true,
        externalId: true,
        country: true,
        _count: { select: { procedures: true } },
      },
      orderBy: { name: "asc" },
    }),
    prisma.malware.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        id: true,
        name: true,
        externalId: true,
        type: true,
        _count: { select: { procedures: true } },
      },
      orderBy: { name: "asc" },
    }),
    prisma.technique.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        id: true,
        name: true,
        externalId: true,
        isSubtechnique: true,
        _count: { select: { procedures: true, atomicTests: true } },
      },
      orderBy: { externalId: "asc" },
    }),
    prisma.category.findMany({
      select: {
        id: true,
        slug: true,
        name: true,
        color: true,
        _count: { select: { techniques: true, actors: true } },
      },
      orderBy: { name: "asc" },
    }),
  ]);

  return {
    actors: actors.map((a) => ({ id: a.id, name: a.name, externalId: a.externalId, country: a.country, procedureCount: a._count.procedures })),
    malware: malware.map((m) => ({ id: m.id, name: m.name, externalId: m.externalId, type: m.type, procedureCount: m._count.procedures })),
    techniques: techniques.map((t) => ({ id: t.id, name: t.name, externalId: t.externalId, isSubtechnique: t.isSubtechnique, procedureCount: t._count.procedures, atomicTestCount: t._count.atomicTests })),
    categories: categories.map((c) => ({ id: c.slug, name: c.name, slug: c.slug, color: c.color, techniqueCount: c._count.techniques, actorCount: c._count.actors })),
  };
}

export async function getTopReportableEntities() {
  const [topActors, topMalware] = await Promise.all([
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        id: true,
        name: true,
        externalId: true,
        country: true,
        _count: { select: { procedures: true } },
      },
      orderBy: { procedures: { _count: "desc" } },
      take: 10,
    }),
    prisma.malware.findMany({
      where: { deprecated: false, revoked: false },
      select: {
        id: true,
        name: true,
        externalId: true,
        type: true,
        _count: { select: { procedures: true } },
      },
      orderBy: { procedures: { _count: "desc" } },
      take: 10,
    }),
  ]);

  return {
    topActors: topActors.map((a) => ({ id: a.id, name: a.name, externalId: a.externalId, country: a.country, procedureCount: a._count.procedures })),
    topMalware: topMalware.map((m) => ({ id: m.id, name: m.name, externalId: m.externalId, type: m.type, procedureCount: m._count.procedures })),
  };
}

// ── Executive Summary Generators ────────────────────────────────────────────

function buildActorExecutiveSummary(opts: {
  name: string;
  aliases: string[];
  country: string | null;
  motivations: string[];
  techniqueCount: number;
  malwareCount: number;
  campaignCount: number;
  tacticsUsed: string[];
  detectionCoverage: number;
}): string {
  const parts: string[] = [];

  let intro = `${opts.name}`;
  if (opts.aliases.length > 0) intro += ` (also known as ${opts.aliases.slice(0, 3).join(", ")})`;
  intro += ` is a threat actor`;
  if (opts.country) intro += ` attributed to ${opts.country}`;
  if (opts.motivations.length > 0) intro += ` with ${opts.motivations.join(", ").toLowerCase()} motivations`;
  intro += ".";
  parts.push(intro);

  parts.push(
    `This actor has been observed using ${opts.techniqueCount} ATT&CK techniques across ${opts.tacticsUsed.length} tactics` +
    (opts.malwareCount > 0 ? `, deploying ${opts.malwareCount} malware families` : "") +
    (opts.campaignCount > 0 ? ` in ${opts.campaignCount} documented campaigns` : "") +
    "."
  );

  if (opts.tacticsUsed.length > 0) {
    parts.push(`Primary tactics include ${opts.tacticsUsed.slice(0, 5).join(", ")}.`);
  }

  if (opts.detectionCoverage < 50) {
    parts.push(`Detection coverage is ${opts.detectionCoverage}% — significant gaps exist that should be addressed.`);
  } else if (opts.detectionCoverage < 80) {
    parts.push(`Detection coverage is ${opts.detectionCoverage}% — moderate coverage with room for improvement.`);
  } else {
    parts.push(`Detection coverage is ${opts.detectionCoverage}% — strong coverage across observed techniques.`);
  }

  return parts.join(" ");
}

function buildMalwareExecutiveSummary(opts: {
  name: string;
  type: string | null;
  aliases: string[];
  actorCount: number;
  actorCountries: string[];
  techniqueCount: number;
  tacticsUsed: string[];
  iocCount: number;
}): string {
  const parts: string[] = [];

  let intro = `${opts.name}`;
  if (opts.aliases.length > 0) intro += ` (${opts.aliases.slice(0, 3).join(", ")})`;
  intro += ` is a ${opts.type ?? "malware"} family`;
  if (opts.actorCount > 0) {
    intro += ` used by ${opts.actorCount} threat actor${opts.actorCount > 1 ? "s" : ""}`;
    if (opts.actorCountries.length > 0) intro += ` from ${opts.actorCountries.join(", ")}`;
  }
  intro += ".";
  parts.push(intro);

  parts.push(
    `It employs ${opts.techniqueCount} ATT&CK techniques spanning ${opts.tacticsUsed.length} tactics.`
  );

  if (opts.iocCount > 0) {
    parts.push(`${opts.iocCount} IOCs have been associated with this malware family.`);
  }

  if (opts.tacticsUsed.length > 0) {
    parts.push(`Key tactics: ${opts.tacticsUsed.slice(0, 5).join(", ")}.`);
  }

  return parts.join(" ");
}

// ── Mitigation Recommendations ──────────────────────────────────────────────

const TACTIC_MITIGATIONS: Record<string, string[]> = {
  "Reconnaissance": [
    "Minimize public exposure of infrastructure details and employee information",
    "Monitor for scanning activity against external-facing assets",
  ],
  "Resource Development": [
    "Implement email authentication (DMARC, DKIM, SPF) to counter phishing infrastructure",
    "Monitor for typosquatting and look-alike domains",
  ],
  "Initial Access": [
    "Deploy email gateway filtering with attachment sandboxing",
    "Enforce MFA on all external-facing services",
    "Conduct regular phishing awareness training",
  ],
  "Execution": [
    "Restrict script execution via AppLocker or WDAC policies",
    "Disable macros in Office documents from untrusted sources",
    "Enable PowerShell Constrained Language Mode",
  ],
  "Persistence": [
    "Monitor registry run keys, scheduled tasks, and startup folders",
    "Audit service installations and WMI event subscriptions",
    "Deploy EDR with behavioral detection for persistence mechanisms",
  ],
  "Privilege Escalation": [
    "Apply least-privilege access controls across all systems",
    "Keep systems patched to prevent local privilege escalation exploits",
    "Monitor for credential dumping tools (Mimikatz, ProcDump)",
  ],
  "Defense Evasion": [
    "Enable tamper protection on EDR/AV solutions",
    "Monitor for process injection and DLL side-loading",
    "Implement AMSI for script-based attack detection",
  ],
  "Credential Access": [
    "Deploy credential guard and LSA protection",
    "Enforce strong password policies and implement PAM",
    "Monitor for Kerberoasting and AS-REP roasting attempts",
  ],
  "Discovery": [
    "Implement network segmentation to limit lateral discovery",
    "Monitor for abnormal AD enumeration queries (BloodHound, SharpHound)",
  ],
  "Lateral Movement": [
    "Restrict admin shares and disable unnecessary remote services",
    "Implement network micro-segmentation",
    "Deploy jump servers for administrative access",
  ],
  "Collection": [
    "Implement DLP controls on sensitive data repositories",
    "Monitor for bulk file access and archiving operations",
  ],
  "Command and Control": [
    "Deploy SSL/TLS inspection on egress traffic",
    "Block known C2 frameworks via threat intelligence feeds",
    "Monitor for DNS tunneling and beaconing patterns",
  ],
  "Exfiltration": [
    "Monitor for large outbound data transfers",
    "Implement egress filtering and data classification",
    "Alert on connections to cloud storage services from sensitive networks",
  ],
  "Impact": [
    "Maintain offline backups with tested restore procedures",
    "Implement ransomware-specific protections (controlled folder access)",
    "Develop and test incident response playbooks",
  ],
};

function buildMitigations(tacticsUsed: string[], _techniqueIds: string[]): string[] {
  const mitigations: string[] = [];
  const seen = new Set<string>();

  for (const tactic of tacticsUsed) {
    const recs = TACTIC_MITIGATIONS[tactic];
    if (recs) {
      for (const r of recs) {
        if (!seen.has(r)) { seen.add(r); mitigations.push(r); }
      }
    }
  }

  if (mitigations.length === 0) {
    mitigations.push(
      "Implement defense-in-depth with EDR, network monitoring, and log aggregation",
      "Conduct regular vulnerability assessments and patch management",
      "Maintain incident response plans with defined escalation procedures",
    );
  }

  return mitigations;
}
