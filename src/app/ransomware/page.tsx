import { getRansomwareData } from "@/actions/ransomware";
import { DRAGONFORCE_SPOTLIGHT } from "@/lib/dragonforce-data";
import Link from "next/link";

export default async function RansomwarePage() {
  const { actors, advisories, techniques } = await getRansomwareData();
  const df = DRAGONFORCE_SPOTLIGHT;

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Ransomware Intelligence</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {actors.length} actors · {techniques.length} techniques · {advisories.length} KEV advisories linked to ransomware
        </p>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="stat-card">
          <div className="stat-value text-red-400">{actors.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Ransomware Actors</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-orange-400">{techniques.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Associated Techniques</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-yellow-400">{advisories.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Ransomware-linked KEVs</div>
        </div>
      </div>

      {/* DragonForce Threat Spotlight */}
      <div className="card border-red-900/50">
        <div className="flex items-center gap-3 mb-4">
          <span className="badge bg-red-900/50 text-red-400 text-xs">THREAT SPOTLIGHT</span>
          <h2 className="text-lg font-bold">{df.group}</h2>
          <span className="text-xs text-[var(--text-secondary)]">
            {df.aliases.map((a) => `aka ${a}`).join(", ")} · First seen {df.firstSeen}
          </span>
          <span className="ml-auto badge bg-red-900/50 text-red-300">{df.model}</span>
        </div>
        <p className="text-sm text-[var(--text-secondary)] mb-6 leading-relaxed">{df.description}</p>

        {/* TURN C2 Deep Dive */}
        <div className="bg-[var(--bg-primary)] rounded-lg border border-[var(--border)] p-5 mb-6">
          <h3 className="text-sm font-bold text-red-400 mb-3">{df.c2Detail.name}</h3>
          <p className="text-xs text-[var(--text-secondary)] mb-4 leading-relaxed">{df.c2Detail.description}</p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-semibold mb-2 text-[var(--text-primary)]">Attack Chain</h4>
              <div className="space-y-2">
                {df.c2Detail.steps.map((step, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="shrink-0 w-5 h-5 rounded-full bg-red-900/50 text-red-400 text-[10px] flex items-center justify-center font-bold">
                      {i + 1}
                    </span>
                    <span className="text-xs text-[var(--text-secondary)] leading-relaxed">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold mb-2 text-[var(--text-primary)]">Why It Evades Detection</h4>
              <div className="space-y-1.5">
                {df.c2Detail.whyItWorks.map((reason, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="shrink-0 text-red-400 text-xs">✕</span>
                    <span className="text-xs text-[var(--text-secondary)] leading-relaxed">{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* TTPs Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 mb-6">
          {df.notableTTPs.map((ttp) => (
            <div key={ttp.name} className="bg-[var(--bg-tertiary)] rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-semibold">{ttp.name}</span>
              </div>
              <p className="text-[10px] text-[var(--text-secondary)] leading-relaxed">{ttp.detail}</p>
              {ttp.mitre && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {ttp.mitre.split(", ").map((t) => (
                    <span key={t} className="badge bg-zinc-800 text-zinc-500 text-[9px]">{t}</span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Notable Attacks & IOCs side by side */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
          <div>
            <h3 className="text-sm font-semibold mb-3">Notable Attacks</h3>
            <div className="space-y-2">
              {df.notableAttacks.map((attack) => (
                <div key={attack.target} className="bg-[var(--bg-tertiary)] rounded-lg p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold">{attack.target}</span>
                    <span className="text-[10px] text-[var(--text-secondary)]">{attack.date}</span>
                  </div>
                  <p className="text-[10px] text-[var(--text-secondary)]">{attack.impact}</p>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold mb-3">Indicators of Compromise</h3>
            <div className="space-y-1 max-h-72 overflow-y-auto">
              {df.c2Detail.iocs.map((ioc, i) => (
                <div key={i} className="flex gap-2 items-start">
                  <span className="badge bg-zinc-800 text-zinc-500 text-[9px] shrink-0 mt-0.5">{ioc.type}</span>
                  <span className="text-[10px] text-[var(--text-secondary)] font-mono break-all">{ioc.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CVEs & Affiliates */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <h3 className="text-sm font-semibold mb-3">BYOVD CVEs Exploited</h3>
            <div className="space-y-2">
              {df.cves.map((cve) => (
                <div key={cve.id} className="flex items-center gap-3">
                  <span className="font-mono text-xs text-[var(--accent)]">{cve.id}</span>
                  <span className="text-[10px] text-[var(--text-secondary)]">{cve.driver}</span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold mb-3">Affiliate Network</h3>
            <div className="space-y-2">
              {df.affiliates.map((a) => (
                <div key={a.name} className="bg-[var(--bg-tertiary)] rounded-lg p-3">
                  <span className="text-xs font-semibold">{a.name}</span>
                  <p className="text-[10px] text-[var(--text-secondary)] mt-1">{a.role}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Ransomware Actors</h2>
          <div className="space-y-1">
            {actors.map((a) => (
              <Link
                key={a.id}
                href={`/actors/${a.id}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                <span className="text-sm">{a.name}</span>
                <div className="text-xs text-[var(--text-secondary)]">
                  {a.procedureCount} proc · {a.campaignCount} campaigns
                </div>
              </Link>
            ))}
          </div>
        </div>

        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Common Techniques</h2>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {techniques.sort((a, b) => b.procedureCount - a.procedureCount).map((t) => (
              <Link
                key={t.id}
                href={`/techniques/${t.id}`}
                className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-[var(--accent)]">{t.externalId}</span>
                  <span className="text-sm">{t.name}</span>
                </div>
                <div className="text-xs text-[var(--text-secondary)]">
                  {t.atomicTestCount > 0 && `${t.atomicTestCount} tests`}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Ransomware-Linked Vulnerabilities (CISA KEV)</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-[var(--text-secondary)] text-xs">
                <th className="pb-2">CVE</th>
                <th className="pb-2">Vulnerability</th>
                <th className="pb-2">Vendor / Product</th>
                <th className="pb-2">Added</th>
              </tr>
            </thead>
            <tbody>
              {advisories.slice(0, 30).map((a) => (
                <tr key={a.id} className="table-row">
                  <td className="py-2 font-mono text-[var(--accent)]">{a.cveId}</td>
                  <td className="py-2 max-w-md truncate">{a.title}</td>
                  <td className="py-2 text-[var(--text-secondary)]">
                    {a.vendorProject} — {a.product}
                  </td>
                  <td className="py-2 text-[var(--text-secondary)]">
                    {a.dateAdded && new Date(a.dateAdded).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {advisories.length > 30 && (
            <p className="text-xs text-[var(--text-secondary)] mt-2">
              Showing 30 of {advisories.length} — <Link href="/advisories?ransomware=true" className="text-[var(--accent)]">view all</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
