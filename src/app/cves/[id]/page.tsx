import { getCveDetail } from "@/actions/cves";
import { notFound } from "next/navigation";
import Link from "next/link";
import { format } from "date-fns";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "\u{1F1F7}\u{1F1FA}", "China": "\u{1F1E8}\u{1F1F3}", "North Korea": "\u{1F1F0}\u{1F1F5}", "Iran": "\u{1F1EE}\u{1F1F7}",
  "Vietnam": "\u{1F1FB}\u{1F1F3}", "India": "\u{1F1EE}\u{1F1F3}", "Pakistan": "\u{1F1F5}\u{1F1F0}", "Turkey": "\u{1F1F9}\u{1F1F7}",
  "Lebanon": "\u{1F1F1}\u{1F1E7}", "South Korea": "\u{1F1F0}\u{1F1F7}", "USA": "\u{1F1FA}\u{1F1F8}",
  "UAE": "\u{1F1E6}\u{1F1EA}", "Israel": "\u{1F1EE}\u{1F1F1}", "Belarus": "\u{1F1E7}\u{1F1FE}", "Brazil": "\u{1F1E7}\u{1F1F7}",
  "Palestine": "\u{1F1F5}\u{1F1F8}", "Colombia": "\u{1F1E8}\u{1F1F4}", "United Kingdom": "\u{1F1EC}\u{1F1E7}",
  "Nigeria": "\u{1F1F3}\u{1F1EC}", "Venezuela": "\u{1F1FB}\u{1F1EA}", "Mexico": "\u{1F1F2}\u{1F1FD}",
};

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-green-900/50 text-green-400",
};

function severityClass(severity: string | null) {
  if (!severity) return "bg-zinc-800 text-zinc-400";
  return SEVERITY_STYLES[severity.toLowerCase()] ?? "bg-zinc-800 text-zinc-400";
}

function cvssSeverityLabel(score: number): string {
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

function cvssSeverityColor(score: number): string {
  if (score >= 9.0) return "text-red-400";
  if (score >= 7.0) return "text-orange-400";
  if (score >= 4.0) return "text-yellow-400";
  return "text-green-400";
}

function epssBadgeClass(score: number): string {
  if (score > 0.7) return "bg-red-900/50 text-red-400";
  if (score > 0.3) return "bg-orange-900/50 text-orange-400";
  return "bg-green-900/50 text-green-400";
}

export default async function CveDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const cve = await getCveDetail(id);
  if (!cve) notFound();

  const hasEpssOrCvss =
    cve.epssScore !== null ||
    cve.cvssScore !== null ||
    cve.publishedDate !== null;

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <span className="text-sm font-mono text-[var(--accent)]">{cve.cveId ?? cve.advisoryId}</span>
        <h1 className="text-2xl font-bold mt-1">{cve.title}</h1>
        <div className="flex gap-2 mt-2 flex-wrap">
          <span className="badge bg-zinc-800 text-zinc-400">{cve.type}</span>
          {cve.severity && (
            <span className={`badge ${severityClass(cve.severity)}`}>{cve.severity}</span>
          )}
          {cve.knownRansomware && (
            <span className="badge bg-red-900/50 text-red-400">Known Ransomware Use</span>
          )}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{cve.description}</p>
      </div>

      {hasEpssOrCvss && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">EPSS / CVSS Scoring</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* EPSS Section */}
            <div className="space-y-3">
              <div className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">
                EPSS (Exploit Prediction)
              </div>
              {cve.epssScore !== null ? (
                <>
                  <div className="flex items-baseline gap-2">
                    <span className={`badge text-base ${epssBadgeClass(cve.epssScore)}`}>
                      {cve.epssScore.toFixed(5)}
                    </span>
                    {cve.epssPercentile !== null && (
                      <span className="text-sm text-[var(--text-secondary)]">
                        ({Math.round(cve.epssPercentile * 100)}th percentile)
                      </span>
                    )}
                  </div>
                  {/* Visual EPSS bar */}
                  <div className="w-full h-2 rounded-full bg-[var(--bg-tertiary)] overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${Math.max(cve.epssScore * 100, 1)}%`,
                        backgroundColor:
                          cve.epssScore > 0.7
                            ? "rgb(248, 113, 113)"
                            : cve.epssScore > 0.3
                            ? "rgb(251, 146, 60)"
                            : "rgb(74, 222, 128)",
                      }}
                    />
                  </div>
                  <p className="text-xs text-[var(--text-secondary)]">
                    Probability of exploitation in the next 30 days
                  </p>
                </>
              ) : (
                <span className="text-sm text-[var(--text-secondary)]">No EPSS data available</span>
              )}
            </div>

            {/* CVSS Section */}
            <div className="space-y-3">
              <div className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">
                CVSS (Severity)
              </div>
              {cve.cvssScore !== null ? (
                <>
                  <div className="flex items-baseline gap-2">
                    <span className={`text-2xl font-bold ${cvssSeverityColor(cve.cvssScore)}`}>
                      {cve.cvssScore.toFixed(1)}
                    </span>
                    <span className={`badge ${severityClass(cvssSeverityLabel(cve.cvssScore).toLowerCase())}`}>
                      {cvssSeverityLabel(cve.cvssScore)}
                    </span>
                  </div>
                  {cve.cvssVector && (
                    <code className="text-xs text-[var(--text-secondary)] break-all block">
                      {cve.cvssVector}
                    </code>
                  )}
                </>
              ) : (
                <span className="text-sm text-[var(--text-secondary)]">No CVSS data available</span>
              )}
            </div>
          </div>

          {/* Published / Modified dates */}
          {(cve.publishedDate || cve.lastModifiedDate) && (
            <div className="flex gap-4 mt-4 pt-4 border-t border-[var(--border)]">
              {cve.publishedDate && (
                <div>
                  <span className="text-xs text-[var(--text-secondary)]">NVD Published: </span>
                  <span className="text-sm">{format(cve.publishedDate, "MMM d, yyyy")}</span>
                </div>
              )}
              {cve.lastModifiedDate && (
                <div>
                  <span className="text-xs text-[var(--text-secondary)]">Last Modified: </span>
                  <span className="text-sm">{format(cve.lastModifiedDate, "MMM d, yyyy")}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <div className="text-xs text-[var(--text-secondary)]">Vendor / Product</div>
          <div className="text-sm mt-1">
            {cve.vendorProject && <span className="badge bg-blue-900/50 text-blue-400 mr-2">{cve.vendorProject}</span>}
            {cve.product && <span className="badge bg-zinc-800 text-zinc-400">{cve.product}</span>}
          </div>
        </div>
        <div className="card">
          <div className="text-xs text-[var(--text-secondary)]">Dates</div>
          <div className="text-sm mt-1">
            {cve.dateAdded && <span>Added: {format(cve.dateAdded, "MMM d, yyyy")}</span>}
            {cve.dueDate && <span> · Due: {format(cve.dueDate, "MMM d, yyyy")}</span>}
          </div>
        </div>
      </div>

      {cve.knownRansomware && (
        <div className="card border-red-900/50">
          <div className="flex items-center gap-2">
            <span className="badge bg-red-900/50 text-red-400">Ransomware</span>
            <span className="text-sm text-red-400">This vulnerability is known to be used in ransomware campaigns.</span>
          </div>
        </div>
      )}

      {cve.actors.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Threat Actors ({cve.actors.length})</h2>
          <div className="space-y-2">
            {cve.actors.map((aa) => (
              <Link
                key={aa.actor.id}
                href={`/actors/${aa.actor.id}`}
                className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                {aa.actor.country && (
                  <span className="text-lg">{COUNTRY_FLAGS[aa.actor.country] ?? ""}</span>
                )}
                <span className="text-sm font-medium">{aa.actor.name}</span>
                {aa.actor.country && (
                  <span className="text-xs text-[var(--text-secondary)]">{aa.actor.country}</span>
                )}
              </Link>
            ))}
          </div>
        </div>
      )}

      {cve.iocs.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Indicators of Compromise ({cve.iocs.length})</h2>
          <div className="space-y-2">
            {cve.iocs.map((ioc) => (
              <div key={ioc.id} className="p-2 border border-[var(--border)] rounded flex items-center gap-3">
                <span className="badge bg-zinc-800 text-zinc-400">{ioc.type}</span>
                <code className="text-sm text-[var(--accent)] break-all">{ioc.value}</code>
                {ioc.description && (
                  <span className="text-xs text-[var(--text-secondary)] ml-auto">{ioc.description}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {cve.url && (
        <a href={cve.url} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--accent)] hover:underline">
          View external reference →
        </a>
      )}

      <Link href="/cves" className="text-sm text-[var(--text-secondary)] hover:underline block">
        ← Back to CVE tracker
      </Link>
    </div>
  );
}
