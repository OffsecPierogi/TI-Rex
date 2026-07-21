import Link from "next/link";
import { getReportableEntities, getTopReportableEntities } from "@/actions/reports";

const TYPE_LABELS: Record<string, string> = {
  actor: "Threat Actor",
  malware: "Malware",
  technique: "Technique",
  category: "Category",
};

export default async function ReportsPage(
  props: { searchParams: Promise<{ type?: string; q?: string }> }
) {
  const { type = "actor", q = "" } = await props.searchParams;

  const [entities, topEntities] = await Promise.all([
    getReportableEntities(),
    getTopReportableEntities(),
  ]);

  const activeType = ["actor", "malware", "technique", "category"].includes(type) ? type : "actor";

  const rawList =
    activeType === "actor" ? entities.actors
    : activeType === "malware" ? entities.malware
    : activeType === "technique" ? entities.techniques
    : entities.categories;

  const filtered = q
    ? rawList.filter((e) =>
        e.name.toLowerCase().includes(q.toLowerCase()) ||
        ("externalId" in e && e.externalId.toLowerCase().includes(q.toLowerCase()))
      )
    : rawList;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Report Builder</h1>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          Generate threat intelligence briefings for actors, malware, techniques, or categories.
        </p>
      </div>

      <div className="card space-y-5">
        <div>
          <p className="text-sm font-medium mb-2 text-[var(--text-secondary)]">Report Type</p>
          <div className="flex gap-2 flex-wrap">
            {(["actor", "malware", "technique", "category"] as const).map((t) => (
              <Link
                key={t}
                href={`/reports?type=${t}`}
                className={`px-4 py-2 rounded-full text-sm font-medium transition-colors border ${
                  activeType === t
                    ? "bg-[var(--accent)] border-[var(--accent)] text-white"
                    : "border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text-primary)]"
                }`}
              >
                {TYPE_LABELS[t]}
              </Link>
            ))}
          </div>
        </div>

        <div>
          <p className="text-sm font-medium mb-2 text-[var(--text-secondary)]">Search {TYPE_LABELS[activeType]}</p>
          <form method="GET" action="/reports">
            <input type="hidden" name="type" value={activeType} />
            <input
              type="search"
              name="q"
              defaultValue={q}
              placeholder={`Filter ${TYPE_LABELS[activeType].toLowerCase()}s…`}
              className="w-full max-w-md"
            />
          </form>
        </div>

        <div>
          <p className="text-sm font-medium mb-2 text-[var(--text-secondary)]">
            {TYPE_LABELS[activeType]}s
            <span className="ml-2 text-xs text-[var(--text-secondary)]">({filtered.length} results)</span>
          </p>
          <div className="max-h-72 overflow-y-auto border border-[var(--border)] rounded-lg divide-y divide-[var(--border)]">
            {filtered.length === 0 && (
              <p className="p-4 text-sm text-[var(--text-secondary)]">No results found.</p>
            )}
            {filtered.slice(0, 100).map((e) => {
              const entityId = activeType === "category" ? (e as { slug: string }).slug : e.id;
              return (
                <div key={e.id} className="flex items-center justify-between px-4 py-2 hover:bg-[var(--bg-tertiary)]">
                  <div className="flex items-center gap-3">
                    {"externalId" in e && (
                      <span className="font-mono text-xs text-[var(--accent)] w-24 shrink-0">{e.externalId}</span>
                    )}
                    {"color" in e && e.color && (
                      <span className="w-3 h-3 rounded-full shrink-0" style={{ background: e.color }} />
                    )}
                    <span className="text-sm">{e.name}</span>
                    {"country" in e && e.country && (
                      <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">{e.country}</span>
                    )}
                    {"type" in e && e.type && (
                      <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">{e.type}</span>
                    )}
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <Link
                      href={`/reports/${activeType}/${entityId}?format=pdf`}
                      className="px-3 py-1 text-xs bg-[var(--accent)] text-white rounded-lg hover:opacity-90 transition-opacity"
                    >
                      PDF Report
                    </Link>
                    <Link
                      href={`/reports/${activeType}/${entityId}?format=md`}
                      className="px-3 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] rounded-lg hover:border-[var(--accent)] hover:text-[var(--text-primary)] transition-colors"
                    >
                      MD
                    </Link>
                    <Link
                      href={`/reports/${activeType}/${entityId}?format=json`}
                      className="px-3 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] rounded-lg hover:border-[var(--accent)] hover:text-[var(--text-primary)] transition-colors"
                    >
                      JSON
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-base font-semibold mb-3">Top Threat Actors</h2>
          <div className="space-y-1">
            {topEntities.topActors.map((a) => (
              <div key={a.id} className="flex items-center justify-between py-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[var(--accent)] w-20">{a.externalId}</span>
                  <Link href={`/reports/actor/${a.id}?format=pdf`} className="text-sm hover:text-[var(--accent)] transition-colors">
                    {a.name}
                  </Link>
                  {a.country && <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">{a.country}</span>}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-secondary)]">{a.procedureCount} proc</span>
                  <Link href={`/reports/actor/${a.id}?format=json`} className="text-[10px] text-[var(--text-secondary)] hover:text-[var(--accent)]">
                    JSON
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="text-base font-semibold mb-3">Top Malware</h2>
          <div className="space-y-1">
            {topEntities.topMalware.map((m) => (
              <div key={m.id} className="flex items-center justify-between py-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[var(--accent)] w-20">{m.externalId}</span>
                  <Link href={`/reports/malware/${m.id}?format=pdf`} className="text-sm hover:text-[var(--accent)] transition-colors">
                    {m.name}
                  </Link>
                  {m.type && <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">{m.type}</span>}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-secondary)]">{m.procedureCount} proc</span>
                  <Link href={`/reports/malware/${m.id}?format=json`} className="text-[10px] text-[var(--text-secondary)] hover:text-[var(--accent)]">
                    JSON
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
