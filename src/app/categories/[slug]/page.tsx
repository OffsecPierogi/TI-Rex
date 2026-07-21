import { prisma } from "@/lib/db";
import { notFound } from "next/navigation";
import Link from "next/link";
import { NavigatorExportButton } from "@/components/NavigatorExport";

export default async function CategoryDetailPage(props: { params: Promise<{ slug: string }> }) {
  const { slug } = await props.params;
  const category = await prisma.category.findUnique({
    where: { slug },
    include: {
      techniques: {
        include: {
          technique: {
            select: {
              id: true,
              externalId: true,
              name: true,
              isSubtechnique: true,
              _count: { select: { procedures: true, atomicTests: true } },
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
              _count: { select: { procedures: true } },
            },
          },
        },
      },
    },
  });

  if (!category) notFound();

  const techniques = category.techniques
    .map((ct) => ct.technique)
    .sort((a, b) => a.externalId.localeCompare(b.externalId));

  const actors = category.actors
    .map((ca) => ca.actor)
    .sort((a, b) => b._count.procedures - a._count.procedures);

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="w-5 h-5 rounded-full" style={{ background: category.color ?? "#666" }} />
          <div>
            <h1 className="text-2xl font-bold">{category.name}</h1>
            <p className="text-sm text-[var(--text-secondary)]">{category.description}</p>
          </div>
        </div>
        <NavigatorExportButton type="category" id={category.slug} />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="stat-card">
          <div className="stat-value" style={{ color: category.color ?? undefined }}>{techniques.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: category.color ?? undefined }}>{actors.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Threat Actors</div>
        </div>
      </div>

      {actors.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Threat Actors ({actors.length})</h2>
          <div className="space-y-1">
            {actors.map((a) => (
              <Link
                key={a.id}
                href={`/actors/${a.id}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs text-[var(--accent)]">{a.externalId}</span>
                  <span className="text-sm">{a.name}</span>
                </div>
                <span className="text-xs text-[var(--text-secondary)]">{a._count.procedures} procedures</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Techniques ({techniques.length})</h2>
        <div className="space-y-1 max-h-[60vh] overflow-y-auto">
          {techniques.map((t) => (
            <Link
              key={t.id}
              href={`/techniques/${t.id}`}
              className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs text-[var(--accent)] w-20">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
                {t.isSubtechnique && <span className="text-[9px] text-[var(--text-secondary)]">sub</span>}
              </div>
              <div className="flex gap-3 text-xs text-[var(--text-secondary)]">
                <span>{t._count.procedures} proc</span>
                <span>{t._count.atomicTests} tests</span>
              </div>
            </Link>
          ))}
        </div>
      </div>

      <Link href="/categories" className="text-sm text-[var(--text-secondary)] hover:underline block">
        ← Back to categories
      </Link>
    </div>
  );
}
