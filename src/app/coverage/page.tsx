import { getCoverageData } from "@/actions/coverage";
import Link from "next/link";

function getCellColor(detectionCount: number): string {
  if (detectionCount >= 3) return "#22c55e";
  if (detectionCount >= 1) return "#eab308";
  return "#ef4444";
}

function getCellBg(detectionCount: number): string {
  if (detectionCount >= 3) return "rgba(34, 197, 94, 0.15)";
  if (detectionCount >= 1) return "rgba(234, 179, 8, 0.15)";
  return "rgba(239, 68, 68, 0.15)";
}

export default async function CoveragePage() {
  const { tactics, stats } = await getCoverageData();

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Detection Coverage Heatmap</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {stats.coveragePercent}% of ATT&CK techniques have at least one detection rule
        </p>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="stat-card">
          <div className="text-2xl font-bold">{stats.totalTechniques}</div>
          <div className="text-xs text-[var(--text-secondary)]">Total Techniques</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-green-400">{stats.coveredTechniques}</div>
          <div className="text-xs text-[var(--text-secondary)]">Covered</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-red-400">{stats.uncoveredTechniques}</div>
          <div className="text-xs text-[var(--text-secondary)]">Uncovered</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold text-[var(--accent)]">{stats.coveragePercent}%</div>
          <div className="text-xs text-[var(--text-secondary)]">Coverage</div>
        </div>
        <div className="stat-card">
          <div className="text-2xl font-bold">{stats.avgDetectionsPerTechnique}</div>
          <div className="text-xs text-[var(--text-secondary)]">Avg Detections/Technique</div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
        <span className="font-semibold">Legend:</span>
        <span className="flex items-center gap-1.5">
          <span
            className="inline-block w-3 h-3 rounded-sm"
            style={{ background: "#22c55e" }}
          />
          3+ detections
        </span>
        <span className="flex items-center gap-1.5">
          <span
            className="inline-block w-3 h-3 rounded-sm"
            style={{ background: "#eab308" }}
          />
          1-2 detections
        </span>
        <span className="flex items-center gap-1.5">
          <span
            className="inline-block w-3 h-3 rounded-sm"
            style={{ background: "#ef4444" }}
          />
          No detections
        </span>
      </div>

      {/* ATT&CK Matrix Heatmap */}
      <div className="overflow-x-auto pb-4">
        <div className="flex gap-2 min-w-max">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="w-48 shrink-0">
              {/* Tactic Header */}
              <div className="sticky top-0 bg-[var(--bg-tertiary)] p-2 rounded-t-lg border border-[var(--border)] text-center z-10">
                <div className="text-xs font-semibold">{tactic.name}</div>
                <div className="text-[10px] text-[var(--text-secondary)]">
                  {tactic.techniques.filter((t) => t.detectionCount > 0).length}/{tactic.techniques.length} covered
                </div>
              </div>
              {/* Technique Cells */}
              <div className="border-x border-b border-[var(--border)] rounded-b-lg max-h-[70vh] overflow-y-auto">
                {tactic.techniques.map((tech) => {
                  const color = getCellColor(tech.detectionCount);
                  const bg = getCellBg(tech.detectionCount);
                  return (
                    <Link
                      key={tech.id}
                      href={`/coverage/${tech.id}`}
                      className="block p-2 border-b border-[var(--border)] hover:brightness-125 transition-all"
                      style={{ background: bg }}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span
                          className="text-[11px] font-mono font-semibold"
                          style={{ color }}
                        >
                          {tech.externalId}
                        </span>
                        <span
                          className="text-[10px] font-bold px-1.5 py-0.5 rounded-full leading-none"
                          style={{
                            background: `${color}30`,
                            color,
                          }}
                        >
                          {tech.detectionCount}
                        </span>
                      </div>
                      <div
                        className="text-xs truncate mt-0.5"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {tech.name}
                      </div>
                    </Link>
                  );
                })}
                {tactic.techniques.length === 0 && (
                  <div className="p-3 text-xs text-[var(--text-secondary)] text-center">
                    No techniques
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
