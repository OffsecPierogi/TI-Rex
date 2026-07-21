import { getStackAnalysis, getIndustryAnalysis } from "@/actions/threat-model";
import { STACK_COMPONENTS, INDUSTRY_PROFILES } from "@/lib/threat-model-data";
import { StackPicker } from "./StackPicker";
import { IndustryPicker } from "./IndustryPicker";
import Link from "next/link";

export default async function ThreatModelPage(props: {
  searchParams: Promise<{ mode?: string; components?: string; industry?: string }>;
}) {
  const searchParams = await props.searchParams;
  const mode = searchParams.mode ?? "stack";
  const selectedComponents = searchParams.components?.split(",").filter(Boolean) ?? [];
  const selectedIndustry = searchParams.industry ?? "";

  const stackResult = mode === "stack" && selectedComponents.length > 0
    ? await getStackAnalysis(selectedComponents)
    : null;

  const industryResult = mode === "industry" && selectedIndustry
    ? await getIndustryAnalysis(selectedIndustry)
    : null;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Threat Model</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Map your attack surface to MITRE ATT&CK techniques and threat actors
        </p>
      </div>

      <div className="flex gap-2">
        <Link href="/threat-model?mode=stack"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === "stack" ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
          }`}>
          By Technology Stack
        </Link>
        <Link href="/threat-model?mode=industry"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === "industry" ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
          }`}>
          By Industry
        </Link>
      </div>

      {mode === "stack" && (
        <>
          <div className="card">
            <StackPicker components={STACK_COMPONENTS} selected={selectedComponents} />
          </div>

          {stackResult && (
            <>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="stat-card">
                  <div className="stat-value text-lg">{stackResult.stats.totalTechniques}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg">{stackResult.stats.totalActors}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Threat Actors</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg">{stackResult.stats.withAtomics}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Have Atomics</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg text-emerald-400">{stackResult.stats.coverage}%</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Detection Coverage</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg text-red-400">{stackResult.stats.gaps}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Detection Gaps</div>
                </div>
              </div>

              {stackResult.byTactic.length > 0 && (
                <div className="card">
                  <h2 className="text-sm font-semibold mb-3">Attack Surface by Tactic</h2>
                  <div className="flex gap-2 flex-wrap">
                    {stackResult.byTactic.sort((a, b) => b.count - a.count).map((t) => (
                      <div key={t.tactic} className="px-3 py-2 rounded-lg bg-[var(--bg-tertiary)] text-sm">
                        <span className="text-[var(--text-primary)] font-medium">{t.count}</span>
                        <span className="text-[var(--text-secondary)] ml-1.5">{t.tactic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {stackResult.actors.length > 0 && (
                <div className="card">
                  <h2 className="text-sm font-semibold mb-3">Threat Actors Targeting Your Stack</h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {stackResult.actors.map((a) => (
                      <Link key={a.id} href={`/actors/${a.id}`}
                        className="flex items-center gap-3 p-3 rounded-lg bg-[var(--bg-tertiary)] hover:border-[var(--accent)] border border-transparent transition-colors">
                        <div className="min-w-0">
                          <div className="text-sm font-medium truncate">{a.name}</div>
                          <div className="text-xs text-[var(--text-secondary)]">
                            {a.country && <span>{a.country}</span>}
                            <span className="ml-2 font-mono text-[var(--accent)]">{a.externalId}</span>
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              <div className="card">
                <h2 className="text-sm font-semibold mb-3">
                  Relevant Techniques ({stackResult.techniques.length})
                </h2>
                <div className="space-y-1">
                  {stackResult.techniques.slice(0, 100).map((t) => (
                    <Link key={t.id} href={`/techniques/${t.id}`}
                      className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="text-xs font-mono text-[var(--accent)] w-24 shrink-0">{t.externalId}</span>
                        <span className="text-sm truncate">{t.name}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {t.atomicTests > 0 && (
                          <span className="badge bg-emerald-900/50 text-emerald-400">{t.atomicTests} atomics</span>
                        )}
                        {t.detections > 0 && (
                          <span className="badge bg-blue-900/50 text-blue-400">{t.detections} detections</span>
                        )}
                        {t.atomicTests > 0 && t.detections === 0 && (
                          <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" title="Detection gap" />
                        )}
                      </div>
                    </Link>
                  ))}
                  {stackResult.techniques.length > 100 && (
                    <p className="text-xs text-[var(--text-secondary)] p-2">
                      + {stackResult.techniques.length - 100} more techniques
                    </p>
                  )}
                </div>
              </div>
            </>
          )}
        </>
      )}

      {mode === "industry" && (
        <>
          <div className="card">
            <p className="text-sm text-[var(--text-secondary)] mb-4">Select your industry</p>
            <IndustryPicker profiles={INDUSTRY_PROFILES} selected={selectedIndustry} />
          </div>

          {industryResult && (
            <>
              <div className="card border-[var(--accent)]">
                <h2 className="text-lg font-semibold">{industryResult.profile.name}</h2>
                <p className="text-sm text-[var(--text-secondary)] mt-1">{industryResult.profile.description}</p>
                <div className="flex gap-2 flex-wrap mt-3">
                  {industryResult.profile.primaryThreats.map((t) => (
                    <span key={t} className="badge bg-red-900/50 text-red-400">{t}</span>
                  ))}
                </div>
                <div className="flex gap-2 flex-wrap mt-2">
                  {industryResult.profile.compliance.map((c) => (
                    <span key={c} className="badge bg-zinc-800 text-zinc-400">{c}</span>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="stat-card">
                  <div className="stat-value text-lg">{industryResult.stats.totalActors}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Threat Actors</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg">{industryResult.stats.totalTechniques}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques</div>
                </div>
                <div className="stat-card">
                  <div className="stat-value text-lg">{industryResult.stats.withDetections}</div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">With Detections</div>
                </div>
                <div className="stat-card">
                  <div className={`stat-value text-lg ${industryResult.stats.coverage >= 50 ? "text-emerald-400" : "text-red-400"}`}>
                    {industryResult.stats.coverage}%
                  </div>
                  <div className="text-xs text-[var(--text-secondary)] mt-1">Coverage</div>
                </div>
              </div>

              <div className="card">
                <h2 className="text-sm font-semibold mb-3">Key Risks</h2>
                <ol className="space-y-2">
                  {industryResult.profile.keyRisks.map((risk, i) => (
                    <li key={i} className="flex gap-3 text-sm">
                      <span className="w-6 h-6 rounded-full bg-red-900/50 text-red-400 flex items-center justify-center text-xs shrink-0 mt-0.5">
                        {i + 1}
                      </span>
                      <span className="text-[var(--text-secondary)]">{risk}</span>
                    </li>
                  ))}
                </ol>
              </div>

              {industryResult.actors.length > 0 && (
                <div className="card">
                  <h2 className="text-sm font-semibold mb-3">
                    Threat Actors ({industryResult.actors.length})
                  </h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                    {industryResult.actors.slice(0, 30).map((a) => (
                      <Link key={a.id} href={`/actors/${a.id}`}
                        className="flex items-center gap-3 p-3 rounded-lg bg-[var(--bg-tertiary)] hover:border-[var(--accent)] border border-transparent transition-colors">
                        <div>
                          <div className="text-sm font-medium">{a.name}</div>
                          <div className="text-xs text-[var(--text-secondary)]">
                            {a.country ?? "Unknown"} · {a.externalId}
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                  {industryResult.actors.length > 30 && (
                    <p className="text-xs text-[var(--text-secondary)] mt-2">
                      + {industryResult.actors.length - 30} more actors
                    </p>
                  )}
                </div>
              )}

              <div className="card">
                <h2 className="text-sm font-semibold mb-3">
                  Relevant Techniques ({industryResult.techniques.length})
                </h2>
                <div className="space-y-1">
                  {industryResult.techniques.slice(0, 80).map((t) => (
                    <Link key={t.id} href={`/techniques/${t.id}`}
                      className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)] transition-colors">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="text-xs font-mono text-[var(--accent)] w-24 shrink-0">{t.externalId}</span>
                        <span className="text-sm truncate">{t.name}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {t.atomicTests > 0 && (
                          <span className="badge bg-emerald-900/50 text-emerald-400">{t.atomicTests} atomics</span>
                        )}
                        {t.detections > 0 && (
                          <span className="badge bg-blue-900/50 text-blue-400">{t.detections} detections</span>
                        )}
                      </div>
                    </Link>
                  ))}
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
