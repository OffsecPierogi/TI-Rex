import { getActors, getCountryCounts } from "@/actions/actors";
import Link from "next/link";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "🇷🇺", "China": "🇨🇳", "North Korea": "🇰🇵", "Iran": "🇮🇷",
  "Vietnam": "🇻🇳", "India": "🇮🇳", "Pakistan": "🇵🇰", "Turkey": "🇹🇷",
  "Lebanon": "🇱🇧", "South Korea": "🇰🇷", "USA": "🇺🇸",
  "UAE": "🇦🇪", "Israel": "🇮🇱", "Belarus": "🇧🇾", "Brazil": "🇧🇷",
  "Palestine": "🇵🇸", "Colombia": "🇨🇴", "United Kingdom": "🇬🇧",
  "Nigeria": "🇳🇬", "Venezuela": "🇻🇪", "Mexico": "🇲🇽",
};

const COUNTRY_COLORS: Record<string, string> = {
  "Russia": "#dc2626", "China": "#f59e0b", "North Korea": "#8b5cf6",
  "Iran": "#10b981", "India": "#f97316",
  "Vietnam": "#06b6d4", "Pakistan": "#22c55e", "Turkey": "#e11d48", "Lebanon": "#84cc16",
  "South Korea": "#3b82f6", "USA": "#1d4ed8", "UAE": "#a855f7",
  "Israel": "#14b8a6", "Belarus": "#ef4444", "Brazil": "#16a34a",
  "Palestine": "#059669", "Colombia": "#eab308", "United Kingdom": "#1e40af",
  "Nigeria": "#15803d", "Venezuela": "#b91c1c", "Mexico": "#047857",
};

export default async function ActorsPage(props: {
  searchParams: Promise<{ page?: string; search?: string; category?: string; country?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const [{ actors, total, pages }, countryCounts] = await Promise.all([
    getActors({
      page,
      search: searchParams.search,
      category: searchParams.category,
      country: searchParams.country,
    }),
    getCountryCounts(),
  ]);

  const activeCountry = searchParams.country ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      category: searchParams.category ?? "",
      country: searchParams.country ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/actors?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Threat Actors</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total.toLocaleString()} actors
          {activeCountry && ` — ${activeCountry}`}
        </p>
      </div>

      <div className="flex gap-2 flex-wrap">
        <Link
          href={buildUrl({ country: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm ${
            !activeCountry ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
          }`}
        >
          All
        </Link>
        {countryCounts.map((c) => (
          <Link
            key={c.country}
            href={buildUrl({ country: activeCountry === c.country ? "" : c.country })}
            className={`px-3 py-1.5 rounded-lg text-sm flex items-center gap-1.5 transition-colors ${
              activeCountry === c.country
                ? "text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
            style={activeCountry === c.country ? { background: COUNTRY_COLORS[c.country] ?? "var(--accent)" } : undefined}
          >
            <span>{COUNTRY_FLAGS[c.country] ?? ""}</span>
            {c.country} ({c.count})
          </Link>
        ))}
      </div>

      <form className="flex gap-3" action="/actors">
        <input type="hidden" name="country" value={activeCountry} />
        <input type="search" name="search" placeholder="Search actors..." defaultValue={searchParams.search ?? ""} className="flex-1" />
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="space-y-1">
        {actors.map((a) => (
          <Link
            key={a.id}
            href={`/actors/${a.id}`}
            className="flex items-center gap-4 p-3 rounded-lg hover:bg-[var(--bg-secondary)] transition-colors"
          >
            <div className="w-8 text-center text-lg shrink-0">
              {COUNTRY_FLAGS[a.country ?? ""] ?? ""}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{a.name}</span>
                {a.country && (
                  <span
                    className="badge text-[10px]"
                    style={{
                      background: `${COUNTRY_COLORS[a.country] ?? "#666"}20`,
                      color: COUNTRY_COLORS[a.country] ?? "#999",
                    }}
                  >
                    {a.country}
                  </span>
                )}
              </div>
              {a.aliases.length > 0 && (
                <div className="text-xs text-[var(--text-secondary)] truncate mt-0.5">
                  aka {a.aliases.slice(0, 4).join(", ")}
                  {a.aliases.length > 4 && ` +${a.aliases.length - 4}`}
                </div>
              )}
              <div className="flex gap-1.5 mt-1 flex-wrap">
                {a.motivations.slice(0, 3).map((m) => (
                  <span key={m} className="badge bg-zinc-800/50 text-zinc-500 text-[10px]">{m}</span>
                ))}
                {a.categories.map((c) => (
                  <span key={c.slug} className="badge" style={{ background: `${c.color}20`, color: c.color ?? undefined }}>
                    {c.name}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex gap-4 text-xs text-[var(--text-secondary)] shrink-0">
              <span className="font-mono">{a.externalId}</span>
              <span>{a.procedureCount} proc</span>
              <span>{a.campaignCount} camp</span>
            </div>
          </Link>
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
