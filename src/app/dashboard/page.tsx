import { getDashboardStats, getRecentUpdates, getTopActors, getCategoryOverview, getCountryBreakdown, getIOCStats } from "@/actions/dashboard";
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

export default async function DashboardPage() {
  const [stats, updates, topActors, categories, countries, iocStats] = await Promise.all([
    getDashboardStats(),
    getRecentUpdates(),
    getTopActors(),
    getCategoryOverview(),
    getCountryBreakdown(),
    getIOCStats(),
  ]);

  const statCards = [
    { label: "Techniques", value: stats.techniques, href: "/techniques" },
    { label: "Threat Actors", value: stats.actors, href: "/actors" },
    { label: "Malware", value: stats.malware, href: "/malware" },
    { label: "Tools", value: stats.tools, href: "/tools" },
    { label: "Atomic Tests", value: stats.atomicTests, href: "/commands" },
    { label: "Advisories (KEV)", value: stats.advisories, href: "/advisories" },
    { label: "IOCs", value: iocStats.total, href: "/iocs" },
    { label: "Detections", value: stats.procedures, href: "/detections" },
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">
          <span className="text-emerald-400">TI</span>-Rex Dashboard
        </h1>
        <p className="text-[var(--text-secondary)] text-sm mt-1">
          Threat intelligence overview — MITRE ATT&CK, Atomic Red Team, CISA KEV
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        {statCards.map((s) => (
          <Link key={s.label} href={s.href} className="stat-card hover:border-[var(--accent)] transition-colors">
            <div className="stat-value">{s.value.toLocaleString()}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">APT Attribution by Country</h2>
          <div className="space-y-2">
            {countries.map((c) => {
              const color = COUNTRY_COLORS[c.country] ?? "#666";
              const total = countries.reduce((s, x) => s + x.count, 0);
              const pct = Math.round((c.count / total) * 100);
              return (
                <Link
                  key={c.country}
                  href={`/actors?country=${encodeURIComponent(c.country)}`}
                  className="block p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span>{COUNTRY_FLAGS[c.country] ?? ""}</span>
                      <span className="text-sm">{c.country}</span>
                    </div>
                    <span className="text-xs text-[var(--text-secondary)]">{c.count} actors</span>
                  </div>
                  <div className="w-full bg-[var(--bg-tertiary)] rounded-full h-1.5">
                    <div className="h-1.5 rounded-full" style={{ width: `${pct}%`, background: color }} />
                  </div>
                </Link>
              );
            })}
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Categories</h2>
          <div className="space-y-2">
            {categories.map((c) => (
              <Link
                key={c.id}
                href={`/categories/${c.slug}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full" style={{ background: c.color ?? "#666" }} />
                  <span className="text-sm">{c.name}</span>
                </div>
                <div className="text-xs text-[var(--text-secondary)]">
                  {c.techniqueCount} tech · {c.actorCount} actors
                </div>
              </Link>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Top Threat Actors</h2>
          <div className="space-y-2">
            {topActors.map((a) => (
              <Link
                key={a.id}
                href={`/actors/${a.id}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                <div className="flex items-center gap-2">
                  {a.country && <span className="text-xs">{COUNTRY_FLAGS[a.country] ?? ""}</span>}
                  <span className="text-sm">{a.name}</span>
                </div>
                <span className="text-xs text-[var(--text-secondary)]">{a.procedureCount} proc</span>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">IOC Breakdown</h2>
          <div className="grid grid-cols-2 gap-3">
            {iocStats.byType.map((t) => (
              <Link
                key={t.type}
                href={`/iocs?type=${t.type}`}
                className="p-3 bg-[var(--bg-tertiary)] rounded-lg hover:border-[var(--accent)] border border-transparent transition-colors"
              >
                <div className="text-xl font-bold">{t.count}</div>
                <div className="text-xs text-[var(--text-secondary)]">
                  {t.type === "ipv4" ? "Malicious IPs" :
                   t.type === "sha256" ? "SHA-256 Hashes" :
                   t.type === "md5" ? "MD5 Hashes" :
                   t.type === "domain" ? "Domains" :
                   t.type === "url" ? "URLs" :
                   t.type.toUpperCase()}
                </div>
              </Link>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Recent Updates</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[var(--text-secondary)] text-xs">
                  <th className="pb-2">Source</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Records</th>
                  <th className="pb-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {updates.map((u) => (
                  <tr key={u.id} className="table-row">
                    <td className="py-2">{u.source}</td>
                    <td className="py-2">
                      <span
                        className={`badge ${
                          u.status === "success"
                            ? "bg-green-900/50 text-green-400"
                            : u.status === "error"
                              ? "bg-red-900/50 text-red-400"
                              : "bg-yellow-900/50 text-yellow-400"
                        }`}
                      >
                        {u.status}
                      </span>
                    </td>
                    <td className="py-2">{u.recordsProcessed.toLocaleString()}</td>
                    <td className="py-2 text-[var(--text-secondary)]">
                      {u.startedAt.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
