import { getCommands, getExecutors, getCategories } from "@/actions/commands";
import Link from "next/link";

export default async function CommandsPage(props: {
  searchParams: Promise<{ page?: string; search?: string; executor?: string; platform?: string; category?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const [{ tests, total, pages }, executors, categories] = await Promise.all([
    getCommands({
      page,
      search: searchParams.search,
      executor: searchParams.executor,
      platform: searchParams.platform,
      category: searchParams.category,
    }),
    getExecutors(),
    getCategories(),
  ]);

  const activeCategory = searchParams.category ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      executor: searchParams.executor ?? "",
      platform: searchParams.platform ?? "",
      category: searchParams.category ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/commands?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Attack Commands</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total.toLocaleString()} atomic tests with real commands
          {activeCategory && ` — filtered by ${categories.find((c) => c.slug === activeCategory)?.name ?? activeCategory}`}
        </p>
      </div>

      <div className="flex gap-2 flex-wrap">
        <Link
          href={buildUrl({ category: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
            !activeCategory ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          All
        </Link>
        {categories.map((c) => (
          <Link
            key={c.slug}
            href={buildUrl({ category: c.slug })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors flex items-center gap-1.5 ${
              activeCategory === c.slug
                ? "text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
            style={activeCategory === c.slug ? { background: c.color ?? "var(--accent)" } : undefined}
          >
            <span className="w-2 h-2 rounded-full" style={{ background: c.color ?? "#666" }} />
            {c.name}
          </Link>
        ))}
      </div>

      <form className="flex gap-3 flex-wrap" action="/commands">
        <input type="hidden" name="category" value={activeCategory} />
        <input type="search" name="search" placeholder="Search commands... (e.g. mimikatz, net user, whoami)" defaultValue={searchParams.search ?? ""} className="flex-1 min-w-[200px]" />
        <select name="executor" defaultValue={searchParams.executor ?? ""}>
          <option value="">All executors</option>
          {executors.map((e) => (
            <option key={e.name} value={e.name}>{e.name} ({e.count})</option>
          ))}
        </select>
        <select name="platform" defaultValue={searchParams.platform ?? ""}>
          <option value="">All platforms</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS</option>
        </select>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="space-y-4">
        {tests.map((t) => (
          <div key={t.id} className="card">
            <div className="flex items-start justify-between mb-2">
              <div>
                <Link href={`/commands/${t.id}`} className="text-sm font-semibold hover:text-[var(--accent)]">
                  {t.name}
                </Link>
                <div className="flex items-center gap-2 mt-1">
                  <Link href={`/techniques/${t.technique.id}`} className="text-xs font-mono text-[var(--accent)] hover:underline">
                    {t.technique.externalId}
                  </Link>
                  <span className="text-xs text-[var(--text-secondary)]">{t.technique.name}</span>
                </div>
              </div>
              <div className="flex gap-2 shrink-0">
                <span className="badge bg-zinc-800 text-zinc-400">{t.executor}</span>
                {t.elevationRequired && <span className="badge bg-red-900/50 text-red-400">elevated</span>}
              </div>
            </div>
            <pre className="code-block">{t.command}</pre>
            <div className="flex gap-1.5 mt-2 flex-wrap">
              {t.platforms.map((p) => (
                <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
              ))}
              {t.categories.map((c) => (
                <Link key={c.slug} href={buildUrl({ category: c.slug })}>
                  <span className="badge" style={{ background: `${c.color}20`, color: c.color ?? undefined }}>
                    {c.name}
                  </span>
                </Link>
              ))}
            </div>
            {t.technique.procedures.length > 0 && (
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                <span className="text-[10px] text-[var(--text-secondary)]">Used by:</span>
                {t.technique.procedures.map((p) => (
                  <Link key={p.actor!.id} href={`/actors/${p.actor!.id}`}>
                    <span className="badge bg-purple-900/30 text-purple-400 text-[10px] hover:bg-purple-900/50">
                      {p.actor!.name}
                    </span>
                  </Link>
                ))}
                {t.technique.procedures.length >= 10 && (
                  <span className="text-[10px] text-[var(--text-secondary)]">+more</span>
                )}
              </div>
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
