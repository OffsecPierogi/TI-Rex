import { getDetections, getDetectionStats } from "@/actions/detections";
import Link from "next/link";
import { DetectionImport } from "@/components/import/DetectionImport";

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

export default async function DetectionsPage(props: {
  searchParams: Promise<{ page?: string; search?: string; language?: string; category?: string; severity?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const [{ rules, total, pages }, stats] = await Promise.all([
    getDetections({
      page,
      search: searchParams.search,
      language: searchParams.language,
      category: searchParams.category,
      severity: searchParams.severity,
    }),
    getDetectionStats(),
  ]);

  const activeCategory = searchParams.category ?? "";
  const activeLanguage = searchParams.language ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      language: searchParams.language ?? "",
      category: searchParams.category ?? "",
      severity: searchParams.severity ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/detections?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Detection Rules</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total} detection rules — KQL, Sigma, Splunk SPL, YARA, Snort
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {stats.byLanguage.map((l) => (
          <Link
            key={l.name}
            href={buildUrl({ language: activeLanguage === l.name ? "" : l.name })}
            className={`stat-card hover:border-[var(--accent)] transition-colors cursor-pointer ${
              activeLanguage === l.name ? "border-[var(--accent)]" : ""
            }`}
          >
            <div className="stat-value text-lg">{l.count}</div>
            <div className="text-xs text-[var(--text-secondary)]">{l.name.toUpperCase()}</div>
          </Link>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        <Link
          href={buildUrl({ category: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm ${
            !activeCategory ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
          }`}
        >
          All Categories
        </Link>
        {stats.byCategory
          .filter((c) => c.name)
          .map((c) => (
            <Link
              key={c.name}
              href={buildUrl({ category: activeCategory === c.name! ? "" : c.name! })}
              className={`px-3 py-1.5 rounded-lg text-sm ${
                activeCategory === c.name ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
              }`}
            >
              {c.name} ({c.count})
            </Link>
          ))}
      </div>

      <DetectionImport categories={stats.byCategory.filter((c) => c.name).map((c) => c.name!)} />

      <form className="flex gap-3 flex-wrap" action="/detections">
        <input type="hidden" name="category" value={activeCategory} />
        <input type="hidden" name="language" value={activeLanguage} />
        <input
          type="search"
          name="search"
          placeholder="Search detections... (e.g. Kerberoasting, DCSync, mimikatz)"
          defaultValue={searchParams.search ?? ""}
          className="flex-1 min-w-[250px]"
        />
        <select name="severity" defaultValue={searchParams.severity ?? ""}>
          <option value="">All severities</option>
          {stats.bySeverity.filter((s) => s.name).map((s) => (
            <option key={s.name} value={s.name!}>{s.name} ({s.count})</option>
          ))}
        </select>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="space-y-4">
        {rules.map((r) => (
          <div key={r.id} className="card">
            <div className="flex items-start justify-between mb-2">
              <div>
                <h3 className="text-sm font-semibold">{r.name}</h3>
                {r.technique && (
                  <Link href={`/techniques/${r.technique.id}`} className="text-xs font-mono text-[var(--accent)] hover:underline mt-0.5 block">
                    {r.technique.externalId} — {r.technique.name}
                  </Link>
                )}
              </div>
              <div className="flex gap-2 shrink-0">
                <span className={`badge ${LANG_STYLES[r.language] ?? "bg-zinc-800 text-zinc-400"}`}>
                  {r.language.toUpperCase()}
                </span>
                {r.severity && (
                  <span className={`badge ${SEV_STYLES[r.severity] ?? "bg-zinc-800 text-zinc-400"}`}>
                    {r.severity}
                  </span>
                )}
                {r.category && (
                  <span className="badge bg-zinc-800 text-zinc-400">{r.category}</span>
                )}
              </div>
            </div>
            {r.description && <p className="text-xs text-[var(--text-secondary)] mb-2">{r.description}</p>}
            <pre className="code-block">{r.query}</pre>
            {r.source && (
              <div className="text-[10px] text-[var(--text-secondary)] mt-2">Source: {r.source}</div>
            )}
          </div>
        ))}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Prev</Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">Page {page} of {pages}</span>
          {page < pages && (
            <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Next</Link>
          )}
        </div>
      )}
    </div>
  );
}
