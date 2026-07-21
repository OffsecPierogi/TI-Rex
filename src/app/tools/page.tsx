import { getTools } from "@/actions/tools";
import Link from "next/link";

export default async function ToolsPage(props: {
  searchParams: Promise<{ page?: string; search?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const { tools, total, pages } = await getTools({
    page,
    search: searchParams.search,
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Offensive Tools</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total.toLocaleString()} tools
        </p>
        <p className="text-xs text-[var(--text-secondary)] mt-1">
          Dual-use and offensive tools tracked by MITRE ATT&CK
        </p>
      </div>

      <form className="flex gap-3" action="/tools">
        <input
          type="search"
          name="search"
          placeholder="Search tools..."
          defaultValue={searchParams.search ?? ""}
          className="flex-1"
        />
        <button
          type="submit"
          className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm"
        >
          Filter
        </button>
      </form>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {tools.map((tool) => (
          <div key={tool.id} className="card flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <Link
                href={`/tools/${tool.id}`}
                className="text-sm font-semibold hover:text-[var(--accent)] transition-colors"
              >
                {tool.name}
              </Link>
              <span className="badge bg-zinc-800 text-zinc-400 shrink-0 ml-2">
                {tool.externalId}
              </span>
            </div>

            {tool.description && (
              <p className="text-xs text-[var(--text-secondary)] line-clamp-2 mb-3">
                {tool.description}
              </p>
            )}

            <div className="mt-auto space-y-2">
              {tool.platforms.length > 0 && (
                <div className="flex gap-1.5 flex-wrap">
                  {tool.platforms.map((p) => (
                    <span
                      key={p}
                      className="badge bg-blue-900/30 text-blue-400 text-[10px]"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              )}

              {tool.aliases.length > 0 && (
                <div className="flex gap-1.5 flex-wrap">
                  {tool.aliases.slice(0, 3).map((a) => (
                    <span
                      key={a}
                      className="badge bg-zinc-800 text-zinc-400 text-[10px]"
                    >
                      {a}
                    </span>
                  ))}
                  {tool.aliases.length > 3 && (
                    <span className="text-[10px] text-[var(--text-secondary)]">
                      +{tool.aliases.length - 3}
                    </span>
                  )}
                </div>
              )}

              <div className="text-xs text-[var(--text-secondary)]">
                {tool.procedureCount} procedures
              </div>
            </div>
          </div>
        ))}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link
              href={`/tools?page=${page - 1}&search=${searchParams.search ?? ""}`}
              className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm"
            >
              Prev
            </Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">
            Page {page} of {pages}
          </span>
          {page < pages && (
            <Link
              href={`/tools?page=${page + 1}&search=${searchParams.search ?? ""}`}
              className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm"
            >
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
