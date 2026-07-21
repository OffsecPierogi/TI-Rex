import { getPurpleTeamDetail } from "@/actions/purple-team";
import { notFound } from "next/navigation";
import Link from "next/link";

const LANG_STYLES: Record<string, string> = {
  kql: "bg-blue-900/50 text-blue-400",
  sigma: "bg-purple-900/50 text-purple-400",
  splunk: "bg-green-900/50 text-green-400",
  yara: "bg-orange-900/50 text-orange-400",
  snort: "bg-red-900/50 text-red-400",
};

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-zinc-800 text-zinc-400",
};

const STATUS_BANNER: Record<string, string> = {
  gap: "bg-red-900/30 border-red-700/50 text-red-300",
  covered: "bg-green-900/30 border-green-700/50 text-green-300",
  "detection-only": "bg-blue-900/30 border-blue-700/50 text-blue-300",
};

const STATUS_ICON: Record<string, string> = {
  gap: "bg-red-500",
  covered: "bg-green-500",
  "detection-only": "bg-blue-500",
};

const STATUS_TITLE: Record<string, string> = {
  gap: "Detection Gap — Attack simulations exist but no detection rules are written",
  covered: "Fully Covered — Both attack simulations and detection rules are present",
  "detection-only": "Detection Only — Detection rules exist but no atomic simulations are available",
};

export default async function PurpleTeamDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const technique = await getPurpleTeamDetail(id);
  if (!technique) notFound();

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <Link href="/purple-team" className="text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
          ← Purple Team Coverage Map
        </Link>
        <div className="flex items-center gap-3 mt-3">
          <span className="text-sm font-mono text-[var(--accent)]">{technique.externalId}</span>
          <div className="flex gap-1.5 flex-wrap">
            {technique.tactics.map((tt) => (
              <span key={tt.tactic.id} className="badge bg-blue-900/30 text-blue-400">
                {tt.tactic.name}
              </span>
            ))}
          </div>
        </div>
        <h1 className="text-2xl font-bold mt-1">{technique.name}</h1>
        <div className="flex gap-2 mt-2 flex-wrap">
          {technique.categories.map((ct) => (
            <span
              key={ct.category.slug}
              className="badge"
              style={{ background: `${ct.category.color}20`, color: ct.category.color ?? undefined }}
            >
              {ct.category.name}
            </span>
          ))}
          {technique.platforms.map((p) => (
            <span key={p} className="badge bg-zinc-800 text-zinc-400">
              {p}
            </span>
          ))}
        </div>
      </div>

      <div className={`rounded-xl border px-5 py-4 flex items-center gap-3 ${STATUS_BANNER[technique.status]}`}>
        <span className={`w-3 h-3 rounded-full shrink-0 ${STATUS_ICON[technique.status]}`} />
        <p className="text-sm font-medium">{STATUS_TITLE[technique.status]}</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            Attack Simulation
            <span className="badge bg-zinc-800 text-zinc-400 text-xs">{technique.atomicTests.length} tests</span>
          </h2>

          {technique.atomicTests.length === 0 ? (
            <div className="card text-sm text-[var(--text-secondary)]">
              No Atomic Red Team tests available for this technique.
            </div>
          ) : (
            <div className="space-y-4">
              {technique.atomicTests.map((test) => (
                <div key={test.id} className="card border border-[var(--border)]">
                  <div className="flex items-start justify-between mb-2">
                    <Link href={`/commands/${test.id}`} className="text-sm font-semibold hover:text-[var(--accent)]">
                      {test.name}
                    </Link>
                    <div className="flex gap-2 shrink-0 ml-2">
                      <span className="badge bg-zinc-800 text-zinc-400">{test.executor}</span>
                      {test.elevationRequired && (
                        <span className="badge bg-red-900/50 text-red-400">elevated</span>
                      )}
                    </div>
                  </div>
                  {test.description && (
                    <p className="text-xs text-[var(--text-secondary)] mb-3 line-clamp-2">{test.description}</p>
                  )}
                  <pre className="code-block text-xs">{test.command}</pre>
                  {test.cleanupCommand && (
                    <details className="mt-2">
                      <summary className="text-xs text-[var(--text-secondary)] cursor-pointer select-none">
                        Cleanup command
                      </summary>
                      <pre className="code-block text-xs mt-1">{test.cleanupCommand}</pre>
                    </details>
                  )}
                  <div className="flex gap-1.5 mt-2 flex-wrap">
                    {(JSON.parse(test.platforms) as string[]).map((p) => (
                      <span key={p} className="badge bg-zinc-800 text-zinc-400 text-[10px]">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="space-y-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            Detection Coverage
            <span className="badge bg-zinc-800 text-zinc-400 text-xs">{technique.detections.length} rules</span>
          </h2>

          {technique.detections.length === 0 ? (
            <div className="card text-sm text-[var(--text-secondary)]">
              No detection rules are mapped to this technique.
            </div>
          ) : (
            <div className="space-y-4">
              {technique.detections.map((d) => (
                <div key={d.id} className="card border border-[var(--border)]">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="text-sm font-semibold">{d.name}</h3>
                    <div className="flex gap-2 shrink-0 ml-2">
                      <span className={`badge ${LANG_STYLES[d.language] ?? "bg-zinc-800 text-zinc-400"}`}>
                        {d.language.toUpperCase()}
                      </span>
                      {d.severity && (
                        <span className={`badge ${SEV_STYLES[d.severity] ?? "bg-zinc-800 text-zinc-400"}`}>
                          {d.severity}
                        </span>
                      )}
                    </div>
                  </div>
                  {d.description && (
                    <p className="text-xs text-[var(--text-secondary)] mb-3 line-clamp-2">{d.description}</p>
                  )}
                  <pre className="code-block text-xs">{d.query}</pre>
                  {d.category && (
                    <div className="text-[10px] text-[var(--text-secondary)] mt-2">{d.category}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Gap Analysis</h2>

        {technique.status === "gap" && (
          <div>
            <p className="text-sm text-red-400 mb-3">
              No detection rules exist for this technique. Consider writing rules to detect the following patterns:
            </p>
            <ul className="space-y-2">
              {technique.suggestedActions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-[var(--text-secondary)]">
                  <span className="text-red-500 shrink-0 mt-0.5">→</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {technique.status === "covered" && (
          <div>
            <p className="text-sm text-green-400 mb-3">
              This technique has detection coverage. Coverage inventory:
            </p>
            <ul className="space-y-2">
              {technique.suggestedActions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-[var(--text-secondary)]">
                  <span className="text-green-500 shrink-0 mt-0.5">✓</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {technique.status === "detection-only" && (
          <div>
            <p className="text-sm text-blue-400 mb-3">
              No atomic tests available. Consider creating simulations to validate these detections.
            </p>
            <ul className="space-y-2">
              {technique.suggestedActions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-[var(--text-secondary)]">
                  <span className="text-blue-500 shrink-0 mt-0.5">→</span>
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {technique.detection && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">MITRE Detection Guidance</h2>
          <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line leading-relaxed">
            {technique.detection}
          </p>
        </div>
      )}

      <div className="flex gap-3 text-sm">
        <Link href={`/techniques/${technique.id}`} className="text-[var(--accent)] hover:underline">
          View full technique →
        </Link>
        {technique.url && (
          <a href={technique.url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] hover:underline">
            MITRE ATT&CK →
          </a>
        )}
      </div>
    </div>
  );
}
