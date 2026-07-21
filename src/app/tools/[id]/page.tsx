import { getToolDetail } from "@/actions/tools";
import { notFound } from "next/navigation";
import Link from "next/link";

export default async function ToolDetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const tool = await getToolDetail(id);
  if (!tool) notFound();

  const techniqueMap = new Map<
    string,
    { id: string; externalId: string; name: string; count: number; hasTests: boolean }
  >();
  for (const p of tool.procedures) {
    const existing = techniqueMap.get(p.technique.id);
    if (existing) {
      existing.count++;
    } else {
      techniqueMap.set(p.technique.id, {
        ...p.technique,
        count: 1,
        hasTests: p.technique._count.atomicTests > 0,
      });
    }
  }
  const topTechniques = [...techniqueMap.values()].sort(
    (a, b) => b.count - a.count
  );

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <span className="badge bg-zinc-800 text-zinc-300">
            {tool.externalId}
          </span>
        </div>
        <h1 className="text-2xl font-bold mt-1">{tool.name}</h1>
        {tool.aliases.length > 0 && (
          <div className="flex gap-2 mt-2 flex-wrap">
            {tool.aliases.map((a) => (
              <span key={a} className="badge bg-zinc-800 text-zinc-400">
                {a}
              </span>
            ))}
          </div>
        )}
        {tool.platforms.length > 0 && (
          <div className="flex gap-2 mt-2 flex-wrap">
            {tool.platforms.map((p) => (
              <span
                key={p}
                className="badge bg-blue-900/30 text-blue-400"
              >
                {p}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="stat-card">
          <div className="stat-value text-lg">{topTechniques.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Techniques
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{tool.procedures.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Procedures
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{tool.atomicTests.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Commands
          </div>
        </div>
      </div>

      {/* Description */}
      {tool.description && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Description</h2>
          <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line leading-relaxed">
            {tool.description}
          </p>
        </div>
      )}

      {/* Techniques Used */}
      {topTechniques.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Techniques Used ({topTechniques.length})
          </h2>
          <div className="space-y-1">
            {topTechniques.map((t) => (
              <Link
                key={t.id}
                href={`/techniques/${t.id}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm text-[var(--accent)]">
                    {t.externalId}
                  </span>
                  <span className="text-sm">{t.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  {t.hasTests && (
                    <span className="badge bg-green-900/30 text-green-400 text-[10px]">
                      has cmds
                    </span>
                  )}
                  <span className="text-xs text-[var(--text-secondary)]">
                    {t.count} procedures
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Attack Commands */}
      {tool.atomicTests.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Attack Commands ({tool.atomicTests.length})
            <span className="text-sm font-normal text-[var(--text-secondary)] ml-2">
              Atomic Red Team tests for this tool&apos;s techniques
            </span>
          </h2>
          <div className="space-y-4 max-h-[80vh] overflow-y-auto">
            {tool.atomicTests.slice(0, 50).map((test) => (
              <div
                key={test.id}
                className="border border-[var(--border)] rounded-lg p-4"
              >
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <Link
                      href={`/commands/${test.id}`}
                      className="text-sm font-semibold hover:text-[var(--accent)]"
                    >
                      {test.name}
                    </Link>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs font-mono text-[var(--accent)]">
                        {test.technique.externalId}
                      </span>
                      <span className="text-xs text-[var(--text-secondary)]">
                        {test.technique.name}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <span className="badge bg-zinc-800 text-zinc-400">
                      {test.executor}
                    </span>
                    {test.elevationRequired && (
                      <span className="badge bg-red-900/50 text-red-400">
                        elevated
                      </span>
                    )}
                  </div>
                </div>
                <pre className="code-block">{test.command}</pre>
                <div className="flex gap-1.5 mt-2">
                  {(JSON.parse(test.platforms) as string[]).map((p) => (
                    <span
                      key={p}
                      className="badge bg-zinc-800 text-zinc-400"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {tool.atomicTests.length > 50 && (
              <p className="text-xs text-[var(--text-secondary)]">
                Showing 50 of {tool.atomicTests.length} commands.
                <Link
                  href={`/commands?search=${encodeURIComponent(tool.name)}`}
                  className="text-[var(--accent)] ml-1"
                >
                  View all →
                </Link>
              </p>
            )}
          </div>
        </div>
      )}

      {/* Procedures */}
      {tool.procedures.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Procedures ({tool.procedures.length})
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {tool.procedures.map((p) => (
              <div
                key={p.id}
                className="p-3 border border-[var(--border)] rounded-lg"
              >
                <Link
                  href={`/techniques/${p.technique.id}`}
                  className="text-sm text-[var(--accent)] hover:underline"
                >
                  {p.technique.externalId} — {p.technique.name}
                </Link>
                <p className="text-xs text-[var(--text-secondary)] mt-1 line-clamp-3">
                  {p.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Link */}
      {tool.url && (
        <a
          href={tool.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-[var(--accent)] hover:underline"
        >
          View on MITRE ATT&CK →
        </a>
      )}
    </div>
  );
}
