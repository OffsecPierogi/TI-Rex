import { getGeoData } from "@/actions/geo";
import Link from "next/link";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "\u{1F1F7}\u{1F1FA}", "China": "\u{1F1E8}\u{1F1F3}", "North Korea": "\u{1F1F0}\u{1F1F5}", "Iran": "\u{1F1EE}\u{1F1F7}",
  "Vietnam": "\u{1F1FB}\u{1F1F3}", "India": "\u{1F1EE}\u{1F1F3}", "Pakistan": "\u{1F1F5}\u{1F1F0}", "Turkey": "\u{1F1F9}\u{1F1F7}",
  "Lebanon": "\u{1F1F1}\u{1F1E7}", "South Korea": "\u{1F1F0}\u{1F1F7}", "USA": "\u{1F1FA}\u{1F1F8}",
  "UAE": "\u{1F1E6}\u{1F1EA}", "Israel": "\u{1F1EE}\u{1F1F1}", "Belarus": "\u{1F1E7}\u{1F1FE}", "Brazil": "\u{1F1E7}\u{1F1F7}",
  "Palestine": "\u{1F1F5}\u{1F1F8}", "Colombia": "\u{1F1E8}\u{1F1F4}",
  "United Kingdom": "\u{1F1EC}\u{1F1E7}", "Nigeria": "\u{1F1F3}\u{1F1EC}", "Venezuela": "\u{1F1FB}\u{1F1EA}", "Mexico": "\u{1F1F2}\u{1F1FD}",
};

function getIntensityStyle(count: number) {
  if (count <= 5) return { background: "rgba(153, 27, 27, 0.3)", border: "1px solid rgba(220, 38, 38, 0.2)" };
  if (count <= 15) return { background: "rgba(153, 27, 27, 0.45)", border: "1px solid rgba(220, 38, 38, 0.35)" };
  if (count <= 30) return { background: "rgba(185, 28, 28, 0.5)", border: "1px solid rgba(220, 38, 38, 0.5)" };
  return { background: "rgba(220, 38, 38, 0.55)", border: "1px solid rgba(239, 68, 68, 0.6)" };
}

function getIntensityLabel(count: number) {
  if (count <= 5) return "Low";
  if (count <= 15) return "Medium";
  if (count <= 30) return "High";
  return "Critical";
}

export default async function GeoPage() {
  const { byCountry, byMotivation, topActors, stats } = await getGeoData();

  const maxMotivation = byMotivation[0]?.count ?? 1;

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Threat Actor Geo Heatmap</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Geographic distribution of attributed threat actors across nation-states
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="stat-value">{stats.totalActors}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Attributed Actors</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.totalCountries}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Countries Represented</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-xl">{COUNTRY_FLAGS[stats.topCountry] ?? ""} {stats.topCountry}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Top Origin</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.avgPerCountry}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Avg Actors / Country</div>
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-4">Heatmap</h2>
        <div className="flex gap-3 mb-4 text-xs text-[var(--text-secondary)]">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded" style={{ background: "rgba(153, 27, 27, 0.3)" }} />
            <span>1-5 (Low)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded" style={{ background: "rgba(153, 27, 27, 0.45)" }} />
            <span>6-15 (Medium)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded" style={{ background: "rgba(185, 28, 28, 0.5)" }} />
            <span>16-30 (High)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded" style={{ background: "rgba(220, 38, 38, 0.55)" }} />
            <span>30+ (Critical)</span>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {byCountry.map((c) => {
            const style = getIntensityStyle(c.actorCount);
            const span = c.actorCount > 30 ? "md:col-span-2" : "";
            return (
              <div
                key={c.country}
                className={`rounded-xl p-4 transition-all hover:scale-[1.02] ${span}`}
                style={style}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{COUNTRY_FLAGS[c.country] ?? "\u{1F3F4}"}</span>
                    <span className="font-semibold text-sm">{c.country}</span>
                  </div>
                  <span className="badge text-xs bg-red-900/60 text-red-300">
                    {c.actorCount} actors
                  </span>
                </div>
                <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                  {getIntensityLabel(c.actorCount)} threat density
                </div>
                <div className="flex flex-wrap gap-1">
                  {c.actors.slice(0, 6).map((a) => (
                    <Link
                      key={a.id}
                      href={`/actors/${a.id}`}
                      className="text-[11px] px-1.5 py-0.5 rounded bg-black/30 text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors truncate max-w-[120px]"
                    >
                      {a.name}
                    </Link>
                  ))}
                  {c.actors.length > 6 && (
                    <span className="text-[11px] px-1.5 py-0.5 text-[var(--text-secondary)]">
                      +{c.actors.length - 6} more
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-4">Country Breakdown</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {byCountry.map((c) => {
            return (
              <div
                key={c.country}
                className="card"
                style={{
                  borderLeftWidth: "3px",
                  borderLeftColor: `rgba(220, 38, 38, ${Math.min(0.3 + c.actorCount / 80, 0.8)})`,
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{COUNTRY_FLAGS[c.country] ?? "\u{1F3F4}"}</span>
                    <span className="font-semibold">{c.country}</span>
                  </div>
                  <span className="badge bg-red-900/50 text-red-300">
                    {c.actorCount} actor{c.actorCount !== 1 ? "s" : ""}
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {c.actors.map((a) => (
                    <Link
                      key={a.id}
                      href={`/actors/${a.id}`}
                      className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded-md bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-primary)] transition-colors"
                    >
                      <span className="font-mono text-[10px] opacity-60">{a.externalId}</span>
                      <span>{a.name}</span>
                    </Link>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-4">Motivation Breakdown</h2>
        <div className="card space-y-3">
          {byMotivation.map((m) => {
            const pct = Math.round((m.count / maxMotivation) * 100);
            return (
              <div key={m.motivation}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm">{m.motivation}</span>
                  <span className="text-xs text-[var(--text-secondary)]">{m.count} actors</span>
                </div>
                <div className="w-full bg-[var(--bg-tertiary)] rounded-full h-2">
                  <div
                    className="h-2 rounded-full transition-all"
                    style={{
                      width: `${pct}%`,
                      background: "linear-gradient(90deg, var(--accent), #6366f1)",
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-4">Top 10 Actors by Procedure Count</h2>
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[var(--text-secondary)] text-xs">
                <th className="pb-3 pr-4">#</th>
                <th className="pb-3 pr-4">Actor</th>
                <th className="pb-3 pr-4">Country</th>
                <th className="pb-3 pr-4">External ID</th>
                <th className="pb-3 text-right">Procedures</th>
              </tr>
            </thead>
            <tbody>
              {topActors.map((a, i) => (
                  <tr key={a.id} className="table-row">
                    <td className="py-2.5 pr-4 text-[var(--text-secondary)]">{i + 1}</td>
                    <td className="py-2.5 pr-4">
                      <Link href={`/actors/${a.id}`} className="hover:text-[var(--accent)] transition-colors">
                        {a.name}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-4">
                      {a.country && (
                        <span className="flex items-center gap-1.5">
                          <span>{COUNTRY_FLAGS[a.country] ?? "\u{1F3F4}"}</span>
                          <span className="badge text-[10px] bg-red-900/50 text-red-300">
                            {a.country}
                          </span>
                        </span>
                      )}
                      {!a.country && <span className="text-[var(--text-secondary)]">-</span>}
                    </td>
                    <td className="py-2.5 pr-4 font-mono text-xs text-[var(--text-secondary)]">{a.externalId}</td>
                    <td className="py-2.5 text-right font-mono">{a.procedureCount}</td>
                  </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
