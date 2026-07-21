import { getC2Detail } from "@/actions/c2";
import { notFound } from "next/navigation";
import Link from "next/link";

const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

export default async function C2DetailPage(props: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await props.params;
  const c2 = await getC2Detail(id);
  if (!c2) notFound();

  // Sort tactic breakdown by canonical ATT&CK order
  const sortedTactics = [...c2.tacticBreakdown].sort((a, b) => {
    const ai = TACTIC_ORDER.indexOf(a.tacticShortName);
    const bi = TACTIC_ORDER.indexOf(b.tacticShortName);
    if (ai === -1 && bi === -1) return a.tacticName.localeCompare(b.tacticName);
    if (ai === -1) return 1;
    if (bi === -1) return -1;
    return ai - bi;
  });

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 flex-wrap mb-1">
          <Link
            href="/c2"
            className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            ← C2 Profiles
          </Link>
          <span className="badge bg-zinc-800 text-zinc-300 font-mono">
            {c2.externalId}
          </span>
          <span
            className={`badge ${
              c2.c2Category === "commercial"
                ? "bg-amber-900/50 text-amber-400"
                : "bg-emerald-900/50 text-emerald-400"
            }`}
          >
            {c2.c2Category === "commercial" ? "Commercial" : "Open Source"}
          </span>
        </div>
        <h1 className="text-2xl font-bold">{c2.name}</h1>

        {/* Platforms */}
        <div className="flex gap-2 mt-2 flex-wrap">
          {c2.platforms.map((p) => (
            <span key={p} className="badge bg-blue-900/30 text-blue-400">
              {p}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="stat-value text-lg">{c2.techniqueCount}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Techniques
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{c2.tacticBreakdown.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Tactics Covered
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{c2.procedureCount}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            MITRE Procedures
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{c2.languages.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Languages
          </div>
        </div>
      </div>

      {/* Description */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
          {c2.description}
        </p>
      </div>

      {/* Metadata: License + Languages + Features */}
      <div className="grid sm:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Licensing</h2>
          <p className="text-sm text-[var(--text-secondary)]">{c2.license}</p>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Implementation Languages</h2>
          <div className="flex gap-2 flex-wrap">
            {c2.languages.map((l) => (
              <span key={l} className="badge bg-zinc-800 text-zinc-300">
                {l}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Key Features */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Key Features</h2>
        <div className="flex gap-2 flex-wrap">
          {c2.keyFeatures.map((f) => (
            <span
              key={f}
              className="badge bg-indigo-900/30 text-indigo-400"
            >
              {f}
            </span>
          ))}
        </div>
      </div>

      {/* Tactic breakdown */}
      {sortedTactics.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Technique Breakdown by Tactic
          </h2>
          <div className="space-y-4">
            {sortedTactics.map((tactic) => (
              <div key={tactic.tacticShortName}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="badge bg-indigo-900/30 text-indigo-400">
                    {tactic.tacticName}
                  </span>
                  <span className="text-xs text-[var(--text-secondary)]">
                    {tactic.techniques.length} technique
                    {tactic.techniques.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="pl-2 space-y-1">
                  {tactic.techniques.map((t) => (
                    <Link
                      key={t.id}
                      href={`/techniques/${t.id}`}
                      className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors"
                    >
                      <span className="font-mono text-sm text-[var(--accent)] w-24 shrink-0">
                        {t.externalId}
                      </span>
                      <span className="text-sm">{t.name}</span>
                      {t.hasTests && (
                        <span className="badge bg-green-900/30 text-green-400 text-[10px] ml-auto shrink-0">
                          has cmds
                        </span>
                      )}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Procedures */}
      {c2.procedures.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            MITRE Procedures ({c2.procedures.length})
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {c2.procedures.map((p) => (
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

      {/* MITRE link */}
      {c2.url && (
        <a
          href={c2.url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-sm text-[var(--accent)] hover:underline"
        >
          View on MITRE ATT&amp;CK →
        </a>
      )}
    </div>
  );
}
