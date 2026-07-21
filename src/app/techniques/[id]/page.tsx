import { getTechniqueDetail } from "@/actions/techniques";
import { notFound } from "next/navigation";
import Link from "next/link";

export default async function TechniqueDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const technique = await getTechniqueDetail(id);
  if (!technique) notFound();

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <div>
        <div className="flex items-center gap-3 mb-2">
          <span className="text-sm font-mono text-[var(--accent)]">{technique.externalId}</span>
          {technique.isSubtechnique && technique.parent && (
            <Link href={`/techniques/${technique.parent.id}`} className="text-xs text-[var(--text-secondary)] hover:underline">
              ← {technique.parent.externalId} {technique.parent.name}
            </Link>
          )}
        </div>
        <h1 className="text-2xl font-bold">{technique.name}</h1>
        <div className="flex gap-2 mt-2 flex-wrap">
          {technique.categories.map((c) => (
            <Link key={c.category.slug} href={`/categories/${c.category.slug}`}>
              <span className="badge" style={{ background: `${c.category.color}20`, color: c.category.color ?? undefined }}>
                {c.category.name}
              </span>
            </Link>
          ))}
          {technique.platforms.map((p) => (
            <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line leading-relaxed">
          {technique.description}
        </p>
      </div>

      {technique.tactics.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Tactics</h2>
          <div className="flex gap-2 flex-wrap">
            {technique.tactics.map((tt) => (
              <span key={tt.tactic.id} className="badge bg-blue-900/30 text-blue-400">
                {tt.tactic.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {technique.children.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Sub-Techniques ({technique.children.length})</h2>
          <div className="space-y-1">
            {technique.children.map((child) => (
              <Link key={child.id} href={`/techniques/${child.id}`} className="flex gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)]">{child.externalId}</span>
                <span className="text-sm">{child.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {technique.atomicTests.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Atomic Tests ({technique.atomicTests.length})</h2>
          <div className="space-y-4">
            {technique.atomicTests.map((test) => (
              <div key={test.id} className="border border-[var(--border)] rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold">{test.name}</h3>
                  <div className="flex gap-2">
                    <span className="badge bg-zinc-800 text-zinc-400">{test.executor}</span>
                    {test.elevationRequired && (
                      <span className="badge bg-red-900/50 text-red-400">requires elevation</span>
                    )}
                  </div>
                </div>
                <p className="text-xs text-[var(--text-secondary)] mb-3">{test.description}</p>
                <pre className="code-block">{test.command}</pre>
                {test.cleanupCommand && (
                  <details className="mt-2">
                    <summary className="text-xs text-[var(--text-secondary)] cursor-pointer">Cleanup command</summary>
                    <pre className="code-block mt-1">{test.cleanupCommand}</pre>
                  </details>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {technique.procedures.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Procedures ({technique.procedures.length})</h2>
          <div className="space-y-2">
            {technique.procedures.map((p) => (
              <div key={p.id} className="p-3 border border-[var(--border)] rounded-lg">
                <div className="flex gap-2 mb-1">
                  {p.actor && (
                    <Link href={`/actors/${p.actor.id}`} className="badge bg-purple-900/30 text-purple-400 hover:underline">
                      {p.actor.name}
                    </Link>
                  )}
                  {p.malware && (
                    <Link href={`/malware/${p.malware.id}`} className="badge bg-red-900/30 text-red-400 hover:bg-red-900/50">
                      {p.malware.name}
                    </Link>
                  )}
                  {p.tool && (
                    <Link href={`/tools/${p.tool.id}`} className="badge bg-orange-900/30 text-orange-400 hover:bg-orange-900/50">
                      {p.tool.name}
                    </Link>
                  )}
                  {p.campaign && <span className="badge bg-cyan-900/30 text-cyan-400">{p.campaign.name}</span>}
                </div>
                <p className="text-xs text-[var(--text-secondary)] line-clamp-3">{p.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {technique.dataSources.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Data Sources</h2>
          <div className="flex gap-2 flex-wrap">
            {technique.dataSources.map((ds) => (
              <span key={ds} className="badge bg-zinc-800 text-zinc-400">{ds}</span>
            ))}
          </div>
        </div>
      )}

      {technique.detection && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Detection Guidance (MITRE)</h2>
          <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line">{technique.detection}</p>
        </div>
      )}

      {technique.detections.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Detection Rules ({technique.detections.length})</h2>
          <div className="space-y-4">
            {technique.detections.map((d) => (
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
        </div>
      )}

      {technique.url && (
        <div className="text-sm">
          <a href={technique.url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] hover:underline">
            View on MITRE ATT&CK →
          </a>
        </div>
      )}
    </div>
  );
}
