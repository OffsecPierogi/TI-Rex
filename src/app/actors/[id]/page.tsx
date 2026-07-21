import { getActorDetail } from "@/actions/actors";
import { notFound } from "next/navigation";
import Link from "next/link";
import { NavigatorExportButton } from "@/components/NavigatorExport";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "🇷🇺", "China": "🇨🇳", "North Korea": "🇰🇵", "Iran": "🇮🇷",
  "Vietnam": "🇻🇳", "India": "🇮🇳", "Pakistan": "🇵🇰", "Turkey": "🇹🇷",
  "Lebanon": "🇱🇧", "South Korea": "🇰🇷", "USA": "🇺🇸",
  "UAE": "🇦🇪", "Israel": "🇮🇱", "Belarus": "🇧🇾", "Brazil": "🇧🇷",
  "Palestine": "🇵🇸", "Colombia": "🇨🇴", "United Kingdom": "🇬🇧",
  "Nigeria": "🇳🇬", "Venezuela": "🇻🇪", "Mexico": "🇲🇽",
};

export default async function ActorDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const actor = await getActorDetail(id);
  if (!actor) notFound();

  const techniqueMap = new Map<string, { id: string; externalId: string; name: string; count: number; hasTests: boolean }>();
  for (const p of actor.procedures) {
    const existing = techniqueMap.get(p.technique.id);
    if (existing) {
      existing.count++;
    } else {
      techniqueMap.set(p.technique.id, { ...p.technique, count: 1, hasTests: p.technique._count.atomicTests > 0 });
    }
  }
  const topTechniques = [...techniqueMap.values()].sort((a, b) => b.count - a.count);

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <span className="text-sm font-mono text-[var(--accent)]">{actor.externalId}</span>
          {actor.country && (
            <span className="flex items-center gap-1.5 badge bg-zinc-800 text-zinc-300">
              <span>{COUNTRY_FLAGS[actor.country] ?? ""}</span>
              {actor.country}
            </span>
          )}
        </div>
        <h1 className="text-2xl font-bold mt-1">{actor.name}</h1>
        {actor.aliases.length > 0 && (
          <div className="flex gap-2 mt-2 flex-wrap">
            {actor.aliases.map((a) => (
              <span key={a} className="badge bg-zinc-800 text-zinc-400">{a}</span>
            ))}
          </div>
        )}
        <div className="flex gap-2 mt-2 flex-wrap">
          {actor.motivations.map((m) => (
            <span key={m} className="badge bg-amber-900/30 text-amber-400">{m}</span>
          ))}
          {actor.categories.map((c) => (
            <Link key={c.category.slug} href={`/categories/${c.category.slug}`}>
              <span className="badge" style={{ background: `${c.category.color}20`, color: c.category.color ?? undefined }}>
                {c.category.name}
              </span>
            </Link>
          ))}
        </div>
        <div className="mt-3">
          <NavigatorExportButton type="actor" id={actor.id} />
        </div>
      </div>

      {actor.country && (
        <div className="grid grid-cols-3 gap-4">
          <div className="stat-card">
            <div className="text-2xl">{COUNTRY_FLAGS[actor.country] ?? ""}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">Attribution: {actor.country}</div>
          </div>
          <div className="stat-card">
            <div className="stat-value text-lg">{topTechniques.length}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques</div>
          </div>
          <div className="stat-card">
            <div className="stat-value text-lg">{actor.campaigns.length}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">Campaigns</div>
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)] whitespace-pre-line leading-relaxed">
          {actor.description}
        </p>
      </div>

      {actor.campaigns.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Campaigns ({actor.campaigns.length})</h2>
          <div className="space-y-2">
            {actor.campaigns.map((ca) => (
              <div key={ca.campaign.id} className="p-3 border border-[var(--border)] rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{ca.campaign.name}</span>
                  <span className="text-xs text-[var(--text-secondary)]">
                    {ca.campaign.firstSeen && new Date(ca.campaign.firstSeen).toLocaleDateString()}
                    {ca.campaign.lastSeen && ` — ${new Date(ca.campaign.lastSeen).toLocaleDateString()}`}
                  </span>
                </div>
                {ca.campaign.description && (
                  <p className="text-xs text-[var(--text-secondary)] mt-1 line-clamp-2">{ca.campaign.description}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {actor.exploitedCves.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Exploited CVEs ({actor.exploitedCves.length})</h2>
          <div className="space-y-2">
            {actor.exploitedCves.map((cve) => (
              <Link
                key={cve.id}
                href={`/cves/${cve.id}`}
                className="flex items-center justify-between p-3 border border-[var(--border)] rounded-lg hover:border-[var(--accent)] transition-colors group"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="font-mono text-sm text-[var(--accent)] shrink-0">{cve.cveId ?? cve.advisoryId}</span>
                  <span className="text-sm text-[var(--text-secondary)] truncate">{cve.title}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0 ml-3">
                  {cve.cvssScore !== null && (
                    <span className={`badge ${
                      cve.cvssScore >= 9.0
                        ? "bg-red-900/50 text-red-400"
                        : cve.cvssScore >= 7.0
                        ? "bg-orange-900/50 text-orange-400"
                        : cve.cvssScore >= 4.0
                        ? "bg-yellow-900/50 text-yellow-400"
                        : "bg-green-900/50 text-green-400"
                    }`}>
                      CVSS {cve.cvssScore.toFixed(1)}
                    </span>
                  )}
                  {cve.severity && (
                    <span className={`badge ${
                      cve.severity.toLowerCase() === "critical"
                        ? "bg-red-900/50 text-red-400"
                        : cve.severity.toLowerCase() === "high"
                        ? "bg-orange-900/50 text-orange-400"
                        : cve.severity.toLowerCase() === "medium"
                        ? "bg-yellow-900/50 text-yellow-400"
                        : "bg-green-900/50 text-green-400"
                    }`}>
                      {cve.severity}
                    </span>
                  )}
                  {cve.knownRansomware && (
                    <span className="badge bg-red-900/50 text-red-400">Ransomware</span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {actor.aptReports.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            APT Reports ({actor.aptReports.length})
            <span className="text-sm font-normal text-[var(--text-secondary)] ml-2">
              from blackorbird/apt_report
            </span>
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {actor.aptReports.map((report) => (
              <a
                key={report.id}
                href={report.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-start justify-between p-3 border border-[var(--border)] rounded-lg hover:border-[var(--accent)] transition-colors group"
              >
                <div className="min-w-0 flex-1">
                  <span className="text-sm font-medium group-hover:text-[var(--accent)] line-clamp-1">
                    {report.title}
                  </span>
                  <span className="text-xs text-[var(--text-secondary)] block mt-0.5 truncate">
                    {report.url}
                  </span>
                </div>
                {report.publishedAt && (
                  <span className="text-xs text-[var(--text-secondary)] shrink-0 ml-3">
                    {new Date(report.publishedAt).toLocaleDateString()}
                  </span>
                )}
              </a>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Techniques Used ({topTechniques.length})</h2>
        <div className="space-y-1">
          {topTechniques.map((t) => (
            <Link
              key={t.id}
              href={`/techniques/${t.id}`}
              className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-[var(--accent)]">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {t.hasTests && <span className="badge bg-green-900/30 text-green-400 text-[10px]">has cmds</span>}
                <span className="text-xs text-[var(--text-secondary)]">{t.count} procedures</span>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {actor.atomicTests.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Attack Commands ({actor.atomicTests.length})
            <span className="text-sm font-normal text-[var(--text-secondary)] ml-2">
              Atomic Red Team tests for this actor&apos;s techniques
            </span>
          </h2>
          <div className="space-y-4 max-h-[80vh] overflow-y-auto">
            {actor.atomicTests.slice(0, 50).map((test) => (
              <div key={test.id} className="border border-[var(--border)] rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <Link href={`/commands/${test.id}`} className="text-sm font-semibold hover:text-[var(--accent)]">
                      {test.name}
                    </Link>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs font-mono text-[var(--accent)]">{test.technique.externalId}</span>
                      <span className="text-xs text-[var(--text-secondary)]">{test.technique.name}</span>
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <span className="badge bg-zinc-800 text-zinc-400">{test.executor}</span>
                    {test.elevationRequired && <span className="badge bg-red-900/50 text-red-400">elevated</span>}
                  </div>
                </div>
                <pre className="code-block">{test.command}</pre>
                <div className="flex gap-1.5 mt-2">
                  {(JSON.parse(test.platforms) as string[]).map((p) => (
                    <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
                  ))}
                </div>
              </div>
            ))}
            {actor.atomicTests.length > 50 && (
              <p className="text-xs text-[var(--text-secondary)]">
                Showing 50 of {actor.atomicTests.length} commands.
                <Link href={`/commands?search=${encodeURIComponent(actor.name)}`} className="text-[var(--accent)] ml-1">View all →</Link>
              </p>
            )}
          </div>
        </div>
      )}

      {actor.procedures.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Procedures ({actor.procedures.length})</h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {actor.procedures.map((p) => (
              <div key={p.id} className="p-3 border border-[var(--border)] rounded-lg">
                <Link href={`/techniques/${p.technique.id}`} className="text-sm text-[var(--accent)] hover:underline">
                  {p.technique.externalId} — {p.technique.name}
                </Link>
                <p className="text-xs text-[var(--text-secondary)] mt-1 line-clamp-3">{p.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {actor.url && (
        <a href={actor.url} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--accent)] hover:underline">
          View on MITRE ATT&CK →
        </a>
      )}
    </div>
  );
}
