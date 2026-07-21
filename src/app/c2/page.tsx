import { getC2Profiles } from "@/actions/c2";
import Link from "next/link";

export default async function C2ProfilesPage(props: {
  searchParams: Promise<{ search?: string; category?: string }>;
}) {
  const searchParams = await props.searchParams;
  const activeCategory = searchParams.category ?? "all";

  const { c2s, total, filtered, commercialCount, openSourceCount, totalUniqueTechniques } =
    await getC2Profiles({
      search: searchParams.search,
      category: activeCategory,
    });

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      category: activeCategory,
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v && v !== "all") params.set(k, v);
    }
    return `/c2?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">C2 Framework Profiles</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {filtered !== total
            ? `${filtered} of ${total} frameworks`
            : `${total} frameworks`}{" "}
          mapped to MITRE ATT&amp;CK techniques
        </p>
        <p className="text-xs text-[var(--text-secondary)] mt-1">
          Command &amp; control frameworks used in adversary simulation and real-world intrusions
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="stat-value text-[var(--accent)]">{total}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">C2 Frameworks</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-amber-400">{commercialCount}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Commercial</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-emerald-400">{openSourceCount}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Open Source</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-purple-400">{totalUniqueTechniques}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques Covered</div>
        </div>
      </div>

      {/* Category filter pills + search */}
      <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center">
        <div className="flex gap-2">
          <Link
            href={buildUrl({ category: "all" })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              activeCategory === "all"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            All ({total})
          </Link>
          <Link
            href={buildUrl({ category: "commercial" })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              activeCategory === "commercial"
                ? "bg-amber-600 text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            Commercial ({commercialCount})
          </Link>
          <Link
            href={buildUrl({ category: "open-source" })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              activeCategory === "open-source"
                ? "bg-emerald-700 text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            Open Source ({openSourceCount})
          </Link>
        </div>

        <form className="flex gap-2 flex-1" action="/c2">
          {activeCategory !== "all" && (
            <input type="hidden" name="category" value={activeCategory} />
          )}
          <input
            type="search"
            name="search"
            placeholder="Search frameworks, languages, features..."
            defaultValue={searchParams.search ?? ""}
            className="flex-1 min-w-[200px]"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm"
          >
            Search
          </button>
        </form>
      </div>

      {/* C2 cards */}
      {c2s.length === 0 ? (
        <div className="card text-center py-12 text-[var(--text-secondary)]">
          No C2 frameworks match your filters.
          {" "}<Link href="/c2" className="text-[var(--accent)] hover:underline">Clear filters</Link>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {c2s.map((c2) => (
            <div key={c2.id} className="card flex flex-col">
              {/* Header row */}
              <div className="flex items-start justify-between mb-2 gap-2">
                <Link
                  href={`/c2/${c2.id}`}
                  className="text-sm font-semibold hover:text-[var(--accent)] transition-colors leading-tight"
                >
                  {c2.name}
                </Link>
                <div className="flex gap-1.5 shrink-0 flex-wrap justify-end">
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
              </div>

              {/* Description */}
              <p className="text-xs text-[var(--text-secondary)] line-clamp-3 mb-3 leading-relaxed">
                {c2.description}
              </p>

              <div className="mt-auto space-y-2">
                {/* Platforms */}
                {c2.platforms.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    {c2.platforms.map((p) => (
                      <span
                        key={p}
                        className="badge bg-blue-900/30 text-blue-400 text-[10px]"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                )}

                {/* Languages */}
                {c2.languages.length > 0 && (
                  <div className="flex gap-1.5 flex-wrap">
                    {c2.languages.map((l) => (
                      <span
                        key={l}
                        className="badge bg-zinc-800 text-zinc-400 text-[10px]"
                      >
                        {l}
                      </span>
                    ))}
                  </div>
                )}

                {/* Key features */}
                <div className="flex gap-1.5 flex-wrap">
                  {c2.keyFeatures.slice(0, 3).map((f) => (
                    <span
                      key={f}
                      className="badge bg-indigo-900/30 text-indigo-400 text-[10px]"
                    >
                      {f}
                    </span>
                  ))}
                  {c2.keyFeatures.length > 3 && (
                    <span className="text-[10px] text-[var(--text-secondary)]">
                      +{c2.keyFeatures.length - 3} more
                    </span>
                  )}
                </div>

                {/* Technique count + top IDs */}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-[var(--text-secondary)]">
                    {c2.techniqueCount} techniques
                  </span>
                  {c2.topTechniqueIds.map((tid) => (
                    <span
                      key={tid}
                      className="font-mono text-[10px] text-[var(--accent)] opacity-80"
                    >
                      {tid}
                    </span>
                  ))}
                </div>

                {/* License + link */}
                <div className="flex items-center justify-between pt-1 border-t border-[var(--border)]">
                  <span className="text-[10px] text-[var(--text-secondary)] truncate mr-2">
                    {c2.license}
                  </span>
                  <Link
                    href={`/c2/${c2.id}`}
                    className="text-xs text-[var(--accent)] hover:underline shrink-0"
                  >
                    View Details →
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
