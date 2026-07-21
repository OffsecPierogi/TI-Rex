import { prisma } from "@/lib/db";
import Link from "next/link";

export default async function SearchPage(props: {
  searchParams: Promise<{ q?: string }>;
}) {
  const searchParams = await props.searchParams;
  const q = searchParams.q ?? "";

  let techniques: { id: string; externalId: string; name: string }[] = [];
  let actors: { id: string; externalId: string; name: string }[] = [];
  let commands: { id: string; name: string; executor: string; technique: { externalId: string } }[] = [];
  let advisories: { id: string; advisoryId: string; title: string; cveId: string | null }[] = [];

  if (q.length >= 2) {
    [techniques, actors, commands, advisories] = await Promise.all([
      prisma.technique.findMany({
        where: {
          OR: [
            { name: { contains: q } },
            { externalId: { contains: q } },
            { description: { contains: q } },
          ],
          deprecated: false,
          revoked: false,
        },
        select: { id: true, externalId: true, name: true },
        take: 20,
      }),
      prisma.threatActor.findMany({
        where: {
          OR: [
            { name: { contains: q } },
            { aliases: { contains: q } },
            { description: { contains: q } },
          ],
          deprecated: false,
          revoked: false,
        },
        select: { id: true, externalId: true, name: true },
        take: 20,
      }),
      prisma.atomicTest.findMany({
        where: {
          OR: [
            { name: { contains: q } },
            { command: { contains: q } },
          ],
        },
        select: { id: true, name: true, executor: true, technique: { select: { externalId: true } } },
        take: 20,
      }),
      prisma.advisory.findMany({
        where: {
          OR: [
            { title: { contains: q } },
            { cveId: { contains: q } },
            { vendorProject: { contains: q } },
          ],
        },
        select: { id: true, advisoryId: true, title: true, cveId: true },
        take: 20,
      }),
    ]);
  }

  const totalResults = techniques.length + actors.length + commands.length + advisories.length;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Search</h1>
      </div>

      <form action="/search">
        <input
          type="search"
          name="q"
          placeholder="Search techniques, actors, commands, CVEs..."
          defaultValue={q}
          className="w-full text-lg"
          autoFocus
        />
      </form>

      {q.length >= 2 && (
        <p className="text-sm text-[var(--text-secondary)]">{totalResults} results for &quot;{q}&quot;</p>
      )}

      {techniques.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Techniques ({techniques.length})</h2>
          <div className="space-y-1">
            {techniques.map((t) => (
              <Link key={t.id} href={`/techniques/${t.id}`} className="flex gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)] w-20">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {actors.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Threat Actors ({actors.length})</h2>
          <div className="space-y-1">
            {actors.map((a) => (
              <Link key={a.id} href={`/actors/${a.id}`} className="flex gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)] w-20">{a.externalId}</span>
                <span className="text-sm">{a.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {commands.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Commands ({commands.length})</h2>
          <div className="space-y-1">
            {commands.map((c) => (
              <Link key={c.id} href={`/commands/${c.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="badge bg-zinc-800 text-zinc-400">{c.executor}</span>
                <span className="font-mono text-xs text-[var(--accent)]">{c.technique.externalId}</span>
                <span className="text-sm truncate">{c.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {advisories.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Advisories ({advisories.length})</h2>
          <div className="space-y-1">
            {advisories.map((a) => (
              <Link key={a.id} href={`/advisories/${a.id}`} className="flex gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)]">{a.cveId ?? a.advisoryId}</span>
                <span className="text-sm truncate">{a.title}</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
