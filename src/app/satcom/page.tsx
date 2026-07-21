import {
  SATCOM_ATTACKS,
  SATCOM_ACTORS,
  SATCOM_RESEARCH,
  GNSS_STATS,
  SATCOM_ADVISORIES,
  SATCOM_FRAMEWORKS,
  KEY_TAKEAWAYS,
  getNationStyle,
  getIssuerStyle,
} from "@/lib/satcom-data";

export default function SatcomPage() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">SATCOM Threat Intelligence</h1>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          Satellite communications threats, APT activity, vulnerability research, and regulatory landscape (2020–2025)
        </p>
      </div>

      <div>
        <h2 className="text-base font-semibold mb-3 text-[var(--text-secondary)] uppercase tracking-wider text-xs">
          GNSS / GPS Spoofing — By the Numbers
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {GNSS_STATS.map((stat) => (
            <div key={stat.label} className="stat-card">
              <div className="stat-value text-lg">{stat.value}</div>
              <div className="text-xs text-[var(--text-secondary)] mt-1 font-medium">{stat.label}</div>
              <div className="text-[10px] text-[var(--text-secondary)] mt-1 opacity-70">{stat.detail}</div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-3">Major Attacks</h2>
        <div className="space-y-3">
          {SATCOM_ATTACKS.map((attack) => (
            <div key={attack.id} className="card">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-sm font-bold">{attack.name}</span>
                    <span className={`badge ${getNationStyle(attack.nation)}`}>{attack.nation}</span>
                    <span className="badge bg-zinc-800 text-zinc-400">{attack.attribution}</span>
                  </div>
                  <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{attack.description}</p>
                  <div className="mt-2 p-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]">
                    <span className="text-xs font-medium text-red-400">Impact: </span>
                    <span className="text-xs text-[var(--text-secondary)]">{attack.impact}</span>
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <span className="text-xs text-[var(--text-secondary)] whitespace-nowrap">{attack.date}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-3">APT Groups Targeting SATCOM</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {SATCOM_ACTORS.map((actor) => (
            <div key={actor.id} className="card">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-sm font-bold">{actor.name}</span>
                <span className={`badge ${getNationStyle(actor.nation)}`}>{actor.nation}</span>
                <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">{actor.agency}</span>
              </div>
              {actor.aliases.length > 0 && (
                <div className="flex gap-1 flex-wrap mb-2">
                  {actor.aliases.map((alias) => (
                    <span key={alias} className="text-[10px] text-[var(--text-secondary)] bg-[var(--bg-tertiary)] px-1.5 py-0.5 rounded">
                      {alias}
                    </span>
                  ))}
                </div>
              )}
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed mb-2">{actor.description}</p>
              <div className="p-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]">
                <span className="text-[10px] font-medium text-[var(--accent)]">SATCOM Activity: </span>
                <span className="text-[10px] text-[var(--text-secondary)]">{actor.satcomActivity}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-3">Key Research</h2>
        <div className="space-y-3">
          {SATCOM_RESEARCH.map((research) => (
            <div key={research.id} className="card">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-bold">{research.title}</span>
                    {research.cost && (
                      <span className="badge bg-emerald-900/50 text-emerald-400">{research.cost} setup</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs text-[var(--accent)]">{research.researcher}</span>
                    <span className="text-xs text-[var(--text-secondary)]">—</span>
                    <span className="text-xs text-[var(--text-secondary)]">{research.org}</span>
                    <span className="text-xs text-[var(--text-secondary)]">({research.year})</span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mb-2">{research.description}</p>
                  <div className="p-2 rounded bg-[var(--bg-tertiary)] border border-[var(--border)]">
                    <span className="text-[10px] font-medium text-amber-400">Significance: </span>
                    <span className="text-[10px] text-[var(--text-secondary)]">{research.significance}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-3">Government Advisories & Regulations</h2>
        <div className="space-y-2">
          {SATCOM_ADVISORIES.map((advisory) => (
            <div key={advisory.id} className="card">
              <div className="flex items-start gap-3">
                <div className="shrink-0 mt-0.5">
                  <span className={`badge ${getIssuerStyle(advisory.issuer)}`}>{advisory.issuer}</span>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{advisory.title}</span>
                    <span className="text-xs text-[var(--text-secondary)] shrink-0">{advisory.date}</span>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] mt-1 leading-relaxed">{advisory.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h2 className="text-lg font-semibold mb-3">Threat Frameworks</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {SATCOM_FRAMEWORKS.map((fw) => (
            <div key={fw.id} className="card">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-sm font-bold text-[var(--accent)]">{fw.name}</span>
              </div>
              <span className="text-xs text-[var(--text-secondary)]">{fw.org}</span>
              <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-2">{fw.description}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="card border-l-4 border-l-[var(--accent)]">
        <h2 className="text-lg font-semibold mb-3">Key Takeaways</h2>
        <ul className="space-y-3">
          {KEY_TAKEAWAYS.map((takeaway, i) => (
            <li key={i} className="flex gap-3 text-sm">
              <span className="text-[var(--accent)] font-bold shrink-0">{i + 1}.</span>
              <span className="text-[var(--text-secondary)] leading-relaxed">{takeaway}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
