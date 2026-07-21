import { getSupplyChainAlerts, getSupplyChainStats } from "@/actions/supply-chain";
import Link from "next/link";
import { formatDistanceToNow } from "date-fns";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-green-900/50 text-green-400",
};

const ECO_STYLES: Record<string, string> = {
  npm: "bg-red-900/30 text-red-400",
  pip: "bg-blue-900/30 text-blue-400",
  pypi: "bg-blue-900/30 text-blue-400",
  go: "bg-cyan-900/30 text-cyan-400",
  maven: "bg-orange-900/30 text-orange-400",
  nuget: "bg-purple-900/30 text-purple-400",
  "crates.io": "bg-amber-900/30 text-amber-400",
  rubygems: "bg-pink-900/30 text-pink-400",
};

export default async function SupplyChainPage(props: {
  searchParams: Promise<{
    page?: string;
    ecosystem?: string;
    severity?: string;
    search?: string;
  }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;

  const [{ items, total, pages }, stats] = await Promise.all([
    getSupplyChainAlerts({
      page,
      ecosystem: searchParams.ecosystem,
      severity: searchParams.severity,
      search: searchParams.search,
    }),
    getSupplyChainStats(),
  ]);

  const activeEco = searchParams.ecosystem ?? "";
  const activeSev = searchParams.severity ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      ecosystem: searchParams.ecosystem ?? "",
      severity: searchParams.severity ?? "",
      search: searchParams.search ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/supply-chain?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Supply Chain Threat Tracker</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Compromised packages, malicious dependencies, and critical ecosystem advisories
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.total.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Total Advisories</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg text-red-400">{stats.malicious.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Critical</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg text-orange-400">{stats.criticalHigh.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Critical + High</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.ecosystems.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Ecosystems</div>
        </div>
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Ecosystem:</span>
        <Link href={buildUrl({ ecosystem: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${!activeEco ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
          All
        </Link>
        {stats.ecosystems.map((e) => (
          <Link key={e.ecosystem} href={buildUrl({ ecosystem: activeEco === e.ecosystem ? "" : e.ecosystem })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeEco === e.ecosystem ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {e.ecosystem} ({e.count})
          </Link>
        ))}

        <span className="w-px h-5 bg-[var(--border)] mx-1" />

        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Severity:</span>
        {["critical", "high", "medium", "low"].map((s) => (
          <Link key={s} href={buildUrl({ severity: activeSev === s ? "" : s })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeSev === s ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {s}
          </Link>
        ))}

        <form className="flex gap-2 ml-auto" action="/supply-chain">
          <input type="hidden" name="ecosystem" value={activeEco} />
          <input type="hidden" name="severity" value={activeSev} />
          <input type="search" name="search" placeholder="Search packages..." defaultValue={searchParams.search ?? ""} className="min-w-[220px]" />
          <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Search</button>
        </form>
      </div>

      <div className="text-xs text-[var(--text-secondary)]">
        {total.toLocaleString()} advisories
      </div>

      <div className="space-y-2">
        {items.map((item) => {
          const aliases: string[] = item.aliases ? JSON.parse(item.aliases) : [];
          return (
            <div key={item.id} className="card">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${ECO_STYLES[item.ecosystem] ?? "bg-zinc-800 text-zinc-400"}`}>
                      {item.ecosystem}
                    </span>
                    <span className="font-mono text-sm text-[var(--accent)] font-semibold">{item.packageName}</span>
                    {item.versions && (
                      <span className="text-xs text-[var(--text-secondary)] font-mono">{item.versions}</span>
                    )}
                    {item.publishedAt && (
                      <span className="text-xs text-[var(--text-secondary)]">
                        {formatDistanceToNow(item.publishedAt, { addSuffix: true })}
                      </span>
                    )}
                    {item.withdrawnAt && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400">Withdrawn</span>
                    )}
                  </div>
                  <div className="text-sm leading-snug">{item.summary}</div>
                  <div className="flex items-center gap-2 mt-2 flex-wrap">
                    {item.severity && (
                      <span className={`badge ${SEVERITY_STYLES[item.severity] ?? "bg-zinc-800 text-zinc-400"}`}>
                        {item.severity}
                      </span>
                    )}
                    {aliases.slice(0, 5).map((a) => (
                      <span key={a} className="badge bg-zinc-800 text-zinc-400 font-mono text-[10px]">{a}</span>
                    ))}
                    {item.url && (
                      <a href={item.url} target="_blank" rel="noopener noreferrer"
                        className="text-[10px] text-[var(--accent)] hover:underline ml-auto">
                        View Advisory
                      </a>
                    )}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
        {items.length === 0 && (
          <div className="card text-center text-[var(--text-secondary)] py-12">
            No supply chain advisories found. Run the ingestion pipeline to populate data.
          </div>
        )}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Prev</Link>}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">Page {page} of {pages}</span>
          {page < pages && <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Next</Link>}
        </div>
      )}
    </div>
  );
}
