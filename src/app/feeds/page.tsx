import { getFeedItems, getFeedStats } from "@/actions/feeds";
import Link from "next/link";
import { formatDistanceToNow, format } from "date-fns";

const SOURCE_STYLES: Record<string, string> = {
  "CrowdStrike": "bg-red-900/50 text-red-400",
  "GuidePoint Security": "bg-emerald-900/50 text-emerald-400",
  "BleepingComputer": "bg-orange-900/50 text-orange-400",
  "The Hacker News": "bg-blue-900/50 text-blue-400",
  "Cisco Talos": "bg-sky-900/50 text-sky-400",
  "Unit 42": "bg-amber-900/50 text-amber-400",
  "SentinelOne Labs": "bg-purple-900/50 text-purple-400",
  "Microsoft Security": "bg-cyan-900/50 text-cyan-400",
  "Recorded Future": "bg-indigo-900/50 text-indigo-400",
  "Proofpoint": "bg-teal-900/50 text-teal-400",
  "Krebs on Security": "bg-rose-900/50 text-rose-400",
  "Red Canary": "bg-red-900/50 text-red-300",
  "Volexity": "bg-violet-900/50 text-violet-400",
  "Elastic Security Labs": "bg-yellow-900/50 text-yellow-400",
  "WeLiveSecurity (ESET)": "bg-lime-900/50 text-lime-400",
};

export default async function FeedsPage(props: {
  searchParams: Promise<{ page?: string; source?: string; search?: string; days?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const days = searchParams.days ? Number(searchParams.days) : undefined;

  const [{ items, total, pages }, stats] = await Promise.all([
    getFeedItems({ page, source: searchParams.source, search: searchParams.search, days }),
    getFeedStats(),
  ]);

  const activeSource = searchParams.source ?? "";
  const activeDays = searchParams.days ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      source: searchParams.source ?? "",
      search: searchParams.search ?? "",
      days: searchParams.days ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/feeds?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Threat Feeds</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total} articles from {stats.bySource.length} sources
          {stats.lastFetched && (
            <span> · Last updated {formatDistanceToNow(stats.lastFetched, { addSuffix: true })}</span>
          )}
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.total}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Total Articles</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.last24h}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Last 24h</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.last7d}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Last 7 Days</div>
        </div>
        {stats.bySource.slice(0, 2).map((s) => (
          <Link key={s.source} href={buildUrl({ source: activeSource === s.source ? "" : s.source })}
            className={`stat-card hover:border-[var(--accent)] transition-colors cursor-pointer ${activeSource === s.source ? "border-[var(--accent)]" : ""}`}>
            <div className="stat-value text-lg">{s.count}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.source}</div>
          </Link>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        <Link href={buildUrl({ source: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${!activeSource ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
          All Sources
        </Link>
        {stats.bySource.map((s) => (
          <Link key={s.source} href={buildUrl({ source: activeSource === s.source ? "" : s.source })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeSource === s.source ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {s.source} ({s.count})
          </Link>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        {[
          { label: "All Time", value: "" },
          { label: "Last 24h", value: "1" },
          { label: "Last 7 Days", value: "7" },
          { label: "Last 30 Days", value: "30" },
        ].map((d) => (
          <Link key={d.value} href={buildUrl({ days: activeDays === d.value ? "" : d.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeDays === d.value || (!activeDays && !d.value) ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {d.label}
          </Link>
        ))}
        <form className="flex gap-2 ml-auto" action="/feeds">
          <input type="hidden" name="source" value={activeSource} />
          <input type="hidden" name="days" value={activeDays} />
          <input type="search" name="search" placeholder="Search articles..." defaultValue={searchParams.search ?? ""} className="min-w-[250px]" />
          <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Search</button>
        </form>
      </div>

      <div className="space-y-3">
        {items.map((item) => (
          <div key={item.id} className="card">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`badge ${SOURCE_STYLES[item.source] ?? "bg-zinc-800 text-zinc-400"}`}>
                    {item.source}
                  </span>
                  {item.publishedAt && (
                    <span className="text-xs text-[var(--text-secondary)]">
                      {formatDistanceToNow(item.publishedAt, { addSuffix: true })}
                    </span>
                  )}
                </div>
                <a href={item.url} target="_blank" rel="noopener noreferrer"
                  className="text-sm font-semibold hover:text-[var(--accent)] transition-colors leading-snug block">
                  {item.title}
                </a>
                {item.summary && (
                  <p className="text-xs text-[var(--text-secondary)] mt-1.5 line-clamp-2">{item.summary.slice(0, 200)}</p>
                )}
                <div className="flex items-center gap-3 mt-2">
                  {item.author && <span className="text-[10px] text-[var(--text-secondary)]">By {item.author}</span>}
                  {item.publishedAt && (
                    <span className="text-[10px] text-[var(--text-secondary)]">{format(item.publishedAt, "MMM d, yyyy")}</span>
                  )}
                  {item.tags.length > 0 && item.tags.slice(0, 4).map((tag) => (
                    <span key={tag} className="badge bg-zinc-800 text-zinc-500 text-[10px]">{tag}</span>
                  ))}
                </div>
              </div>
              <a href={item.url} target="_blank" rel="noopener noreferrer"
                className="shrink-0 text-xs px-3 py-1.5 rounded-lg bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors border border-[var(--border)]">
                Read
              </a>
            </div>
          </div>
        ))}
        {items.length === 0 && (
          <div className="card text-center text-[var(--text-secondary)] py-12">
            No articles found. Run <code className="text-[var(--accent)]">npm run update</code> to fetch feeds.
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
