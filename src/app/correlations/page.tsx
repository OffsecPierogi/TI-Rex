import { getCorrelations, getCorrelationStats } from "@/actions/correlations";
import Link from "next/link";

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  ipv4: { bg: "bg-red-900/50", text: "text-red-400", label: "IPv4" },
  ipv6: { bg: "bg-red-900/50", text: "text-red-400", label: "IPv6" },
  sha256: { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-256" },
  md5: { bg: "bg-purple-900/50", text: "text-purple-400", label: "MD5" },
  sha1: { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-1" },
  domain: { bg: "bg-blue-900/50", text: "text-blue-400", label: "Domain" },
  url: { bg: "bg-cyan-900/50", text: "text-cyan-400", label: "URL" },
};

export default async function CorrelationsPage(props: {
  searchParams: Promise<{ page?: string; type?: string; search?: string; min?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const minSources = Number(searchParams.min) || 2;

  const [{ hits, total, pages }, stats] = await Promise.all([
    getCorrelations({
      page,
      type: searchParams.type,
      search: searchParams.search,
      minSources,
    }),
    getCorrelationStats(),
  ]);

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      type: searchParams.type ?? "",
      min: searchParams.min ?? "2",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v && v !== "2") params.set(k, v);
      else if (k === "min" && v === "2") {} // default, skip
      else if (v) params.set(k, v);
    }
    return `/correlations?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Feed Correlation Engine</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Cross-references IOCs across {stats.sourceCounts.length} feeds to surface multi-source intelligence hits
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.totalIOCs.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)]">Total IOCs</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg text-red-400">{stats.multiSourceHits.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)]">Multi-Source Hits</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.sourceCounts.length}</div>
          <div className="text-xs text-[var(--text-secondary)]">Active Feeds</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg text-amber-400">{stats.topMalware.length}</div>
          <div className="text-xs text-[var(--text-secondary)]">Linked Families</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card">
          <h2 className="text-sm font-semibold mb-3">IOCs by Feed Source</h2>
          <div className="space-y-1.5">
            {stats.sourceCounts.map((s) => {
              const pct = stats.totalIOCs > 0 ? (s.count / stats.totalIOCs) * 100 : 0;
              return (
                <div key={s.source} className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-secondary)] w-24 truncate shrink-0">{s.source}</span>
                  <div className="flex-1 h-2 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
                    <div className="h-full bg-[var(--accent)] rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs text-[var(--text-secondary)] w-12 text-right">{s.count}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h2 className="text-sm font-semibold mb-3">Top Linked Malware Families</h2>
          {stats.topMalware.length > 0 ? (
            <div className="space-y-1.5">
              {stats.topMalware.map((m) => (
                <div key={m.name} className="flex items-center justify-between py-1">
                  <span className="text-sm">{m.name}</span>
                  <span className="badge bg-purple-900/30 text-purple-400">{m.iocCount} IOCs</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[var(--text-secondary)]">No malware family links found in IOC descriptions.</p>
          )}
        </div>
      </div>

      <form className="flex gap-3 flex-wrap" action="/correlations">
        <input
          type="search"
          name="search"
          placeholder="Search IOC values..."
          defaultValue={searchParams.search ?? ""}
          className="flex-1 min-w-[200px]"
        />
        <select name="type" defaultValue={searchParams.type ?? ""}>
          <option value="">All types</option>
          <option value="ipv4">IPv4</option>
          <option value="domain">Domain</option>
          <option value="sha256">SHA-256</option>
          <option value="md5">MD5</option>
          <option value="url">URL</option>
        </select>
        <select name="min" defaultValue={String(minSources)}>
          <option value="2">2+ sources</option>
          <option value="3">3+ sources</option>
          <option value="4">4+ sources</option>
        </select>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div>
        <h2 className="text-lg font-semibold mb-3">
          Multi-Source Correlations
          <span className="text-sm font-normal text-[var(--text-secondary)] ml-2">({total} IOCs seen in {minSources}+ feeds)</span>
        </h2>

        {hits.length === 0 ? (
          <div className="card text-center py-12">
            <p className="text-[var(--text-secondary)]">No IOCs found in {minSources}+ sources. Try lowering the threshold.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {hits.map((hit) => {
              const style = TYPE_STYLES[hit.type] ?? { bg: "bg-zinc-800", text: "text-zinc-400", label: hit.type };
              return (
                <div key={`${hit.type}:${hit.value}`} className="card">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-3 min-w-0">
                      <span className={`badge ${style.bg} ${style.text} shrink-0`}>{style.label}</span>
                      <code className="text-sm text-[var(--accent)] font-mono break-all">{hit.value}</code>
                    </div>
                    <span className="badge bg-red-900/50 text-red-400 shrink-0">{hit.sourceCount} feeds</span>
                  </div>

                  <div className="flex gap-2 flex-wrap mb-2">
                    {hit.sources.map((s) => (
                      <div key={s.source} className="px-2 py-1 bg-[var(--bg-tertiary)] rounded text-xs">
                        <span className="font-medium">{s.source}</span>
                        {s.description && (
                          <span className="text-[var(--text-secondary)] ml-1 truncate max-w-[200px] inline-block align-bottom">
                            — {s.description}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>

                  {(hit.malwareLinks.length > 0 || hit.actorLinks.length > 0 || hit.advisoryLinks.length > 0) && (
                    <div className="flex gap-2 flex-wrap pt-2 border-t border-[var(--border)]">
                      {hit.malwareLinks.map((m) => (
                        <Link key={m.id} href={`/malware/${m.id}`}>
                          <span className="badge bg-purple-900/30 text-purple-400 hover:bg-purple-900/50 cursor-pointer">
                            {m.name}
                            {m.type && <span className="text-[10px] ml-1 opacity-70">{m.type}</span>}
                          </span>
                        </Link>
                      ))}
                      {hit.actorLinks.map((a) => (
                        <Link key={a.id} href={`/actors/${a.id}`}>
                          <span className="badge bg-red-900/30 text-red-400 hover:bg-red-900/50 cursor-pointer">
                            {a.name}
                            {a.country && <span className="text-[10px] ml-1 opacity-70">{a.country}</span>}
                          </span>
                        </Link>
                      ))}
                      {hit.advisoryLinks.map((a) => (
                        <Link key={a.id} href={`/advisories/${a.id}`}>
                          <span className="badge bg-amber-900/30 text-amber-400 hover:bg-amber-900/50 cursor-pointer">
                            {a.advisoryId}
                          </span>
                        </Link>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Prev
            </Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">
            Page {page} of {pages}
          </span>
          {page < pages && (
            <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
