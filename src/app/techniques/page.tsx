import { getTechniques } from "@/actions/techniques";
import Link from "next/link";

export default async function TechniquesPage(props: {
  searchParams: Promise<{ page?: string; search?: string; matrix?: string; category?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const { techniques, total, pages } = await getTechniques({
    page,
    search: searchParams.search,
    matrix: searchParams.matrix,
    category: searchParams.category,
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Techniques</h1>
          <p className="text-sm text-[var(--text-secondary)]">{total.toLocaleString()} techniques</p>
        </div>
      </div>

      <form className="flex gap-3" action="/techniques">
        <input type="search" name="search" placeholder="Search techniques..." defaultValue={searchParams.search ?? ""} className="flex-1" />
        <select name="matrix" defaultValue={searchParams.matrix ?? ""}>
          <option value="">All matrices</option>
          <option value="enterprise-attack">Enterprise</option>
          <option value="mobile-attack">Mobile</option>
          <option value="ics-attack">ICS</option>
        </select>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="space-y-1">
        {techniques.map((t) => (
          <Link
            key={t.id}
            href={`/techniques/${t.id}`}
            className="flex items-center gap-4 p-3 rounded-lg hover:bg-[var(--bg-secondary)] transition-colors"
          >
            <span className="text-sm font-mono text-[var(--accent)] w-24 shrink-0">{t.externalId}</span>
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium truncate">
                {t.isSubtechnique && t.parentName && (
                  <span className="text-[var(--text-secondary)]">{t.parentName}: </span>
                )}
                {t.name}
              </div>
              <div className="flex gap-1.5 mt-1 flex-wrap">
                {t.categories.map((c) => (
                  <span key={c.slug} className="badge" style={{ background: `${c.color}20`, color: c.color ?? undefined }}>
                    {c.name}
                  </span>
                ))}
                {t.platforms.slice(0, 3).map((p) => (
                  <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
                ))}
              </div>
            </div>
            <div className="flex gap-4 text-xs text-[var(--text-secondary)] shrink-0">
              <span>{t.procedureCount} proc</span>
              <span>{t.atomicTestCount} tests</span>
              {t.childCount > 0 && <span>{t.childCount} subs</span>}
            </div>
          </Link>
        ))}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={`/techniques?page=${page - 1}&search=${searchParams.search ?? ""}&matrix=${searchParams.matrix ?? ""}`} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Prev
            </Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">
            Page {page} of {pages}
          </span>
          {page < pages && (
            <Link href={`/techniques?page=${page + 1}&search=${searchParams.search ?? ""}&matrix=${searchParams.matrix ?? ""}`} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
