"use server";

import { prisma } from "@/lib/db";

interface GeoActor {
  id: string;
  name: string;
  externalId: string;
}

interface CountryData {
  country: string;
  actorCount: number;
  actors: GeoActor[];
}

interface MotivationData {
  motivation: string;
  count: number;
}

interface TopActor {
  id: string;
  name: string;
  externalId: string;
  country: string | null;
  procedureCount: number;
}

interface GeoStats {
  totalActors: number;
  totalCountries: number;
  topCountry: string;
  avgPerCountry: number;
}

export async function getGeoData(): Promise<{
  byCountry: CountryData[];
  byMotivation: MotivationData[];
  topActors: TopActor[];
  stats: GeoStats;
}> {
  const [actors, topActorsRaw] = await Promise.all([
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false, country: { not: null } },
      select: {
        id: true,
        name: true,
        externalId: true,
        country: true,
        motivations: true,
      },
    }),
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false },
      include: { _count: { select: { procedures: true } } },
      orderBy: { procedures: { _count: "desc" } },
      take: 10,
    }),
  ]);

  const countryMap = new Map<string, GeoActor[]>();
  const motivationMap = new Map<string, number>();

  for (const actor of actors) {
    const country = actor.country!;
    if (!countryMap.has(country)) countryMap.set(country, []);
    countryMap.get(country)!.push({
      id: actor.id,
      name: actor.name,
      externalId: actor.externalId,
    });

    if (actor.motivations) {
      try {
        const motives = JSON.parse(actor.motivations) as string[];
        for (const m of motives) {
          motivationMap.set(m, (motivationMap.get(m) ?? 0) + 1);
        }
      } catch {
      }
    }
  }

  const byCountry: CountryData[] = Array.from(countryMap.entries())
    .map(([country, actorList]) => ({
      country,
      actorCount: actorList.length,
      actors: actorList.sort((a, b) => a.name.localeCompare(b.name)),
    }))
    .sort((a, b) => b.actorCount - a.actorCount);

  const byMotivation: MotivationData[] = Array.from(motivationMap.entries())
    .map(([motivation, count]) => ({ motivation, count }))
    .sort((a, b) => b.count - a.count);

  const topActors: TopActor[] = topActorsRaw.map((a) => ({
    id: a.id,
    name: a.name,
    externalId: a.externalId,
    country: a.country,
    procedureCount: a._count.procedures,
  }));

  const totalActors = actors.length;
  const totalCountries = countryMap.size;

  const stats: GeoStats = {
    totalActors,
    totalCountries,
    topCountry: byCountry[0]?.country ?? "N/A",
    avgPerCountry: totalCountries > 0 ? Math.round((totalActors / totalCountries) * 10) / 10 : 0,
  };

  return { byCountry, byMotivation, topActors, stats };
}
