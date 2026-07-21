import { getTechniqueDetections } from "@/actions/coverage";
import { notFound } from "next/navigation";
import Link from "next/link";

const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(239, 68, 68, 0.2)", text: "#ef4444" },
  high: { bg: "rgba(249, 115, 22, 0.2)", text: "#f97316" },
  medium: { bg: "rgba(234, 179, 8, 0.2)", text: "#eab308" },
  low: { bg: "rgba(34, 197, 94, 0.2)", text: "#22c55e" },
  informational: { bg: "rgba(96, 165, 250, 0.2)", text: "#60a5fa" },
};

const LANGUAGE_COLORS: Record<string, { bg: string; text: string }> = {
  sigma: { bg: "rgba(168, 85, 247, 0.2)", text: "#a855f7" },
  kql: { bg: "rgba(59, 130, 246, 0.2)", text: "#3b82f6" },
  spl: { bg: "rgba(236, 72, 153, 0.2)", text: "#ec4899" },
  yara: { bg: "rgba(34, 197, 94, 0.2)", text: "#22c55e" },
  eql: { bg: "rgba(249, 115, 22, 0.2)", text: "#f97316" },
  snort: { bg: "rgba(239, 68, 68, 0.2)", text: "#ef4444" },
};

function getSeverityStyle(severity: string | null) {
  if (!severity) return { bg: "rgba(161, 161, 170, 0.2)", text: "#a1a1aa" };
  return SEVERITY_COLORS[severity.toLowerCase()] ?? { bg: "rgba(161, 161, 170, 0.2)", text: "#a1a1aa" };
}

function getLanguageStyle(language: string) {
  return LANGUAGE_COLORS[language.toLowerCase()] ?? { bg: "rgba(161, 161, 170, 0.2)", text: "#a1a1aa" };
}

export default async function TechniqueDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const technique = await getTechniqueDetections(id);
  if (!technique) notFound();

  const isCovered = technique.detections.length > 0;
  const platforms = technique.platforms
    ? technique.platforms.split(",").map((p) => p.trim()).filter(Boolean)
    : [];

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div>
        <Link
          href="/coverage"
          className="text-sm text-[var(--text-secondary)] hover:text-[var(--accent)] transition-colors"
        >
          &larr; Back to Coverage Heatmap
        </Link>
        <div className="flex items-center gap-3 mt-3 mb-2">
          <span className="text-sm font-mono text-[var(--accent)]">{technique.externalId}</span>
          <span
            className="badge text-xs font-semibold"
            style={{
              background: isCovered ? "rgba(34, 197, 94, 0.2)" : "rgba(239, 68, 68, 0.2)",
              color: isCovered ? "#22c55e" : "#ef4444",
            }}
          >
            {isCovered ? "Covered" : "Uncovered"}
          </span>
        </div>
        <h1 className="text-2xl font-bold">{technique.name}</h1>
        <div className="flex gap-2 mt-2 flex-wrap">
          {technique.tactics.map((t) => (
            <span key={t.id} className="badge bg-blue-900/30 text-blue-400">
              {t.name}
            </span>
          ))}
          {platforms.map((p) => (
            <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
          ))}
        </div>
      </div>

      {/* Description */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line leading-relaxed">
          {technique.description}
        </p>
      </div>

      {/* Detection Rules */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">
          Detection Rules ({technique.detections.length})
        </h2>
        {technique.detections.length === 0 ? (
          <div className="text-center py-8">
            <div className="text-4xl mb-2">&#x26A0;</div>
            <p className="text-sm text-[var(--text-secondary)]">
              No detection rules exist for this technique. This is a coverage gap.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {technique.detections.map((rule) => {
              const sevStyle = getSeverityStyle(rule.severity);
              const langStyle = getLanguageStyle(rule.language);
              return (
                <div
                  key={rule.id}
                  className="border border-[var(--border)] rounded-lg p-4 bg-[var(--bg-secondary)]"
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <h3 className="text-sm font-semibold">{rule.name}</h3>
                    <div className="flex gap-1.5 shrink-0">
                      <span
                        className="badge text-[10px]"
                        style={{ background: langStyle.bg, color: langStyle.text }}
                      >
                        {rule.language}
                      </span>
                      {rule.severity && (
                        <span
                          className="badge text-[10px]"
                          style={{ background: sevStyle.bg, color: sevStyle.text }}
                        >
                          {rule.severity}
                        </span>
                      )}
                    </div>
                  </div>
                  {rule.description && (
                    <p className="text-xs text-[var(--text-secondary)] mb-3">{rule.description}</p>
                  )}
                  {rule.source && (
                    <p className="text-[10px] text-[var(--text-secondary)] mb-2">
                      Source: <span className="font-medium text-[var(--text-primary)]">{rule.source}</span>
                    </p>
                  )}
                  <pre className="text-xs bg-[var(--bg-tertiary)] border border-[var(--border)] rounded-lg p-3 overflow-x-auto whitespace-pre-wrap break-words">
                    <code>{rule.query}</code>
                  </pre>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Sub-Technique Coverage */}
      {technique.subTechniques.total > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">
            Sub-Technique Coverage
          </h2>
          <p className="text-sm text-[var(--text-secondary)] mb-4">
            {technique.subTechniques.covered} of {technique.subTechniques.total} sub-techniques have detection rules
          </p>
          <div className="space-y-1">
            {technique.subTechniques.items.map((sub) => {
              const hasCoverage = sub.detectionCount > 0;
              return (
                <Link
                  key={sub.id}
                  href={`/coverage/${sub.id}`}
                  className="flex items-center justify-between p-2 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ background: hasCoverage ? "#22c55e" : "#ef4444" }}
                    />
                    <span className="text-xs font-mono text-[var(--accent)]">{sub.externalId}</span>
                    <span className="text-xs">{sub.name}</span>
                  </div>
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded-full"
                    style={{
                      background: hasCoverage ? "rgba(34, 197, 94, 0.2)" : "rgba(239, 68, 68, 0.2)",
                      color: hasCoverage ? "#22c55e" : "#ef4444",
                    }}
                  >
                    {sub.detectionCount}
                  </span>
                </Link>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
