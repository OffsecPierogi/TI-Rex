import { prisma } from "@/lib/db";
import { getMatrixData } from "@/actions/matrix";
import { InteractiveNavigator } from "./InteractiveNavigator";

export default async function NavigatorPage() {
  const [matrixData, actors, malwareList, categories] = await Promise.all([
    getMatrixData("enterprise-attack"),
    prisma.threatActor.findMany({
      where: { deprecated: false, revoked: false, procedures: { some: {} } },
      select: { id: true, name: true, externalId: true, country: true, _count: { select: { procedures: true } } },
      orderBy: { procedures: { _count: "desc" } },
    }),
    prisma.malware.findMany({
      where: { deprecated: false, revoked: false, procedures: { some: {} } },
      select: { id: true, name: true, externalId: true, type: true, _count: { select: { procedures: true } } },
      orderBy: { procedures: { _count: "desc" } },
      take: 100,
    }),
    prisma.category.findMany({
      include: { _count: { select: { techniques: true } } },
      orderBy: { name: "asc" },
    }),
  ]);

  return (
    <InteractiveNavigator
      matrixData={matrixData}
      actors={actors.map((a) => ({
        id: a.id,
        name: a.name,
        externalId: a.externalId,
        country: a.country,
        techniqueCount: a._count.procedures,
      }))}
      malware={malwareList.map((m) => ({
        id: m.id,
        name: m.name,
        externalId: m.externalId,
        type: m.type,
        techniqueCount: m._count.procedures,
      }))}
      categories={categories.map((c) => ({
        slug: c.slug,
        name: c.name,
        color: c.color,
        techniqueCount: c._count.techniques,
      }))}
    />
  );
}
