"use server";

import { prisma } from "@/lib/db";
import {
  actorToStix,
  malwareToStix,
  techniqueToStix,
  iocToStix,
  procedureToStix,
  buildBundle,
} from "@/lib/stix-export";

export async function getStixExportOptions() {
  const [actors, malware, techniques, iocs, campaigns] = await Promise.all([
    prisma.threatActor.count({ where: { deprecated: false, revoked: false } }),
    prisma.malware.count({ where: { deprecated: false, revoked: false } }),
    prisma.technique.count({ where: { deprecated: false, revoked: false } }),
    prisma.iOC.count(),
    prisma.campaign.count(),
  ]);
  return { actors, malware, techniques, iocs, campaigns };
}

export async function getExportableActors() {
  return prisma.threatActor.findMany({
    where: { deprecated: false, revoked: false },
    select: {
      id: true,
      externalId: true,
      name: true,
      country: true,
      _count: { select: { procedures: true } },
    },
    orderBy: { name: "asc" },
  });
}

export async function exportActorStix(actorId: string) {
  const actor = await prisma.threatActor.findUnique({
    where: { id: actorId },
    include: {
      procedures: {
        include: {
          technique: { select: { id: true, stixId: true, externalId: true, name: true, description: true, url: true, platforms: true, isSubtechnique: true, createdAt: true, updatedAt: true, tactics: { include: { tactic: { select: { shortName: true } } } } } },
          actor: { select: { stixId: true } },
          malware: { select: { stixId: true } },
          tool: { select: { stixId: true } },
          campaign: { select: { stixId: true } },
        },
        take: 500,
      },
      malwareLinks: {
        include: {
          malware: true,
        },
      },
    },
  });

  if (!actor) return null;

  const objects: Record<string, unknown>[] = [];

  objects.push(...actorToStix(actor));

  const seenTechniques = new Set<string>();
  for (const proc of actor.procedures) {
    if (!seenTechniques.has(proc.technique.externalId)) {
      seenTechniques.add(proc.technique.externalId);
      objects.push(...techniqueToStix(proc.technique));
    }
  }

  for (const link of actor.malwareLinks) {
    objects.push(...malwareToStix(link.malware));
  }

  return buildBundle(objects);
}

export async function exportBulkStix(
  type: "actors" | "malware" | "techniques" | "iocs",
  limit = 100,
) {
  const objects: Record<string, unknown>[] = [];

  if (type === "actors") {
    const actors = await prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false },
      include: {
        procedures: {
          include: {
            technique: { select: { stixId: true, externalId: true } },
            actor: { select: { stixId: true } },
            malware: { select: { stixId: true } },
            tool: { select: { stixId: true } },
            campaign: { select: { stixId: true } },
          },
        },
      },
      take: limit,
      orderBy: { name: "asc" },
    });
    for (const actor of actors) {
      objects.push(...actorToStix(actor));
    }
  } else if (type === "malware") {
    const items = await prisma.malware.findMany({
      where: { deprecated: false, revoked: false },
      take: limit,
      orderBy: { name: "asc" },
    });
    for (const m of items) {
      objects.push(...malwareToStix(m));
    }
  } else if (type === "techniques") {
    const items = await prisma.technique.findMany({
      where: { deprecated: false, revoked: false },
      include: {
        tactics: { include: { tactic: { select: { shortName: true } } } },
      },
      take: limit,
      orderBy: { externalId: "asc" },
    });
    for (const t of items) {
      objects.push(...techniqueToStix(t));
    }
  } else if (type === "iocs") {
    const items = await prisma.iOC.findMany({
      take: limit,
      orderBy: { createdAt: "desc" },
    });
    for (const ioc of items) {
      objects.push(...iocToStix(ioc));
    }
  }

  return buildBundle(objects);
}

export async function exportFullStix() {
  const [actors, malwareItems, techniques, iocs, procedures] = await Promise.all([
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false },
      take: 200,
      orderBy: { name: "asc" },
    }),
    prisma.malware.findMany({
      where: { deprecated: false, revoked: false },
      take: 200,
      orderBy: { name: "asc" },
    }),
    prisma.technique.findMany({
      where: { deprecated: false, revoked: false },
      include: {
        tactics: { include: { tactic: { select: { shortName: true } } } },
      },
      take: 300,
      orderBy: { externalId: "asc" },
    }),
    prisma.iOC.findMany({
      take: 500,
      orderBy: { createdAt: "desc" },
    }),
    prisma.procedure.findMany({
      include: {
        technique: { select: { stixId: true, externalId: true } },
        actor: { select: { stixId: true } },
        malware: { select: { stixId: true } },
        tool: { select: { stixId: true } },
        campaign: { select: { stixId: true } },
      },
      take: 2000,
    }),
  ]);

  const objects: Record<string, unknown>[] = [];

  for (const a of actors) objects.push(...actorToStix(a));
  for (const m of malwareItems) objects.push(...malwareToStix(m));
  for (const t of techniques) objects.push(...techniqueToStix(t));
  for (const i of iocs) objects.push(...iocToStix(i));
  for (const p of procedures) objects.push(...procedureToStix(p));

  return buildBundle(objects);
}
