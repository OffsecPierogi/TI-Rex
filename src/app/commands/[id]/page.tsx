import { getCommandDetail } from "@/actions/commands";
import { notFound } from "next/navigation";
import Link from "next/link";

export default async function CommandDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const test = await getCommandDetail(id);
  if (!test) notFound();

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <Link href={`/techniques/${test.technique.id}`} className="text-sm font-mono text-[var(--accent)] hover:underline">
          {test.technique.externalId} — {test.technique.name}
        </Link>
        <h1 className="text-2xl font-bold mt-2">{test.name}</h1>
        <div className="flex gap-2 mt-2">
          <span className="badge bg-zinc-800 text-zinc-400">{test.executor}</span>
          {test.elevationRequired && <span className="badge bg-red-900/50 text-red-400">requires elevation</span>}
          {test.platforms.map((p) => (
            <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)]">{test.description}</p>
      </div>

      {test.technique.tactics.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Kill Chain Phase</h2>
          <div className="flex gap-2 flex-wrap">
            {test.technique.tactics.map((tt) => (
              <span key={tt.tactic.id} className="badge bg-blue-900/30 text-blue-400">
                {tt.tactic.name}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Command</h2>
        <pre className="code-block">{test.command}</pre>
      </div>

      {test.cleanupCommand && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Cleanup Command</h2>
          <pre className="code-block">{test.cleanupCommand}</pre>
        </div>
      )}

      {test.inputArguments && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Input Arguments</h2>
          <div className="space-y-2">
            {Object.entries(test.inputArguments as Record<string, { description: string; type: string; default: string }>).map(
              ([key, arg]) => (
                <div key={key} className="p-3 border border-[var(--border)] rounded-lg">
                  <div className="flex items-center gap-2">
                    <code className="text-sm text-[var(--accent)]">{key}</code>
                    <span className="badge bg-zinc-800 text-zinc-400">{arg.type}</span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-1">{arg.description}</p>
                  {arg.default && (
                    <code className="text-xs text-zinc-400 mt-1 block">default: {arg.default}</code>
                  )}
                </div>
              ),
            )}
          </div>
        </div>
      )}

      {test.technique.procedures.length > 0 && (() => {
        const actorProcs = test.technique.procedures.filter((p) => p.actor);
        const malwareProcs = test.technique.procedures.filter((p) => p.malware);
        const toolProcs = test.technique.procedures.filter((p) => p.tool);
        return (
          <div className="card">
            <h2 className="text-lg font-semibold mb-3">Used By</h2>
            {actorProcs.length > 0 && (
              <div className="mb-4">
                <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Threat Actors ({actorProcs.length})</h3>
                <div className="space-y-2">
                  {actorProcs.map((p, i) => (
                    <div key={i} className="flex items-start gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                      <Link href={`/actors/${p.actor!.id}`} className="badge bg-purple-900/30 text-purple-400 hover:bg-purple-900/50 shrink-0">
                        {p.actor!.name}
                      </Link>
                      {p.actor!.country && (
                        <span className="badge bg-zinc-800 text-zinc-400 text-[10px] shrink-0">{p.actor!.country}</span>
                      )}
                      {p.description && (
                        <p className="text-xs text-[var(--text-secondary)] line-clamp-2">{p.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {malwareProcs.length > 0 && (
              <div className="mb-4">
                <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Malware ({malwareProcs.length})</h3>
                <div className="flex gap-2 flex-wrap">
                  {malwareProcs.map((p, i) => (
                    <Link key={i} href={`/malware/${p.malware!.id}`} className="badge bg-red-900/30 text-red-400 hover:bg-red-900/50">
                      {p.malware!.name}
                    </Link>
                  ))}
                </div>
              </div>
            )}
            {toolProcs.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Tools ({toolProcs.length})</h3>
                <div className="flex gap-2 flex-wrap">
                  {toolProcs.map((p, i) => (
                    <Link key={i} href={`/tools/${p.tool!.id}`} className="badge bg-orange-900/30 text-orange-400 hover:bg-orange-900/50">
                      {p.tool!.name}
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {test.technique.categories.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Categories</h2>
          <div className="flex gap-2 flex-wrap">
            {test.technique.categories.map((c) => (
              <Link key={c.category.slug} href={`/categories/${c.category.slug}`}>
                <span className="badge" style={{ background: `${c.category.color}20`, color: c.category.color ?? undefined }}>
                  {c.category.name}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {test.technique.detections.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Detection Rules ({test.technique.detections.length})</h2>
          <div className="space-y-4">
            {test.technique.detections.map((d) => (
              <div key={d.id} className="border border-[var(--border)] rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold">{d.name}</h3>
                  <div className="flex gap-2">
                    <span className={`badge ${
                      d.language === "kql" ? "bg-blue-900/50 text-blue-400" :
                      d.language === "sigma" ? "bg-purple-900/50 text-purple-400" :
                      d.language === "splunk" ? "bg-green-900/50 text-green-400" :
                      d.language === "yara" ? "bg-orange-900/50 text-orange-400" :
                      d.language === "snort" ? "bg-red-900/50 text-red-400" :
                      "bg-zinc-800 text-zinc-400"
                    }`}>{d.language.toUpperCase()}</span>
                    {d.severity && (
                      <span className={`badge ${
                        d.severity === "critical" ? "bg-red-900/50 text-red-400" :
                        d.severity === "high" ? "bg-orange-900/50 text-orange-400" :
                        d.severity === "medium" ? "bg-yellow-900/50 text-yellow-400" :
                        "bg-zinc-800 text-zinc-400"
                      }`}>{d.severity}</span>
                    )}
                  </div>
                </div>
                {d.description && <p className="text-xs text-[var(--text-secondary)] mb-2">{d.description}</p>}
                <pre className="code-block">{d.query}</pre>
              </div>
            ))}
          </div>
          <Link href="/detections" className="text-xs text-[var(--accent)] hover:underline mt-3 block">
            View all detection rules →
          </Link>
        </div>
      )}
    </div>
  );
}
