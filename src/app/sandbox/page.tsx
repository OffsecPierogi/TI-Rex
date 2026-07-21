import { getRecentAnalyses } from "@/actions/sandbox";
import { SandboxSearch } from "./SandboxSearch";

export default async function SandboxPage(props: {
  searchParams: Promise<{ q?: string; iocId?: string }>;
}) {
  const searchParams = await props.searchParams;
  const recent = await getRecentAnalyses();

  function scoreColor(score: number) {
    if (score === 0) return "text-green-400";
    if (score <= 5) return "text-yellow-400";
    if (score <= 15) return "text-orange-400";
    return "text-red-400";
  }

  function timeAgo(date: Date) {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Sandbox Analysis</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Query VirusTotal & Hybrid Analysis — enter a hash, IP, or domain
        </p>
      </div>

      <SandboxSearch initialQuery={searchParams.q} initialIocId={searchParams.iocId} />

      {recent.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Recent Analyses</h2>
          <div className="space-y-1">
            {recent.map((r) => (
              <div key={r.id} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className={`badge text-xs ${
                  r.source === "virustotal" ? "bg-blue-900/30 text-blue-400" : "bg-green-900/30 text-green-400"
                }`}>
                  {r.source === "virustotal" ? "VT" : "HA"}
                </span>
                <code className="text-sm font-mono text-[var(--text-primary)] truncate max-w-[300px]">
                  {r.indicator}
                </code>
                <span className={`text-sm font-bold ${scoreColor(r.score)}`}>{r.score}</span>
                {r.verdict && (
                  <span className="text-xs text-[var(--text-secondary)] truncate max-w-[150px]">{r.verdict}</span>
                )}
                {r.malwareFamily && (
                  <span className="badge bg-red-900/30 text-red-400 text-[10px]">{r.malwareFamily}</span>
                )}
                <span className="text-[10px] text-[var(--text-secondary)] ml-auto shrink-0">
                  {timeAgo(r.fetchedAt)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
