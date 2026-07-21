import { notFound } from "next/navigation";
import Link from "next/link";
import {
  generateActorReport,
  generateMalwareReport,
  generateTechniqueReport,
  generateCategoryReport,
  type ReportType,
} from "@/actions/reports";
import { reportToMarkdown } from "@/lib/report-markdown";
import { ReportActions } from "./ReportActions";

const PRINT_STYLES = `
@media print {
  body { background: white !important; color: black !important; }
  aside, nav, button, .no-print { display: none !important; }
  main { margin: 0 !important; padding: 0 !important; }
  .card { border: 1px solid #ccc !important; background: white !important; break-inside: avoid; }
  .code-block { background: #f5f5f5 !important; color: #333 !important; border: 1px solid #ddd !important; }
  .badge { border: 1px solid #999 !important; background: #eee !important; color: #333 !important; }
  h1, h2, h3 { color: black !important; }
  a { color: #333 !important; text-decoration: underline !important; }
  .page-break { break-before: page; }
}
`;

export default async function ReportDetailPage(
  props: {
    params: Promise<{ type: string; id: string }>;
    searchParams: Promise<{ format?: string }>;
  }
) {
  const { type, id } = await props.params;
  const { format } = await props.searchParams;

  const validTypes: ReportType[] = ["actor", "malware", "technique", "category"];
  if (!validTypes.includes(type as ReportType)) notFound();

  let data: Awaited<ReturnType<typeof generateActorReport>> | Awaited<ReturnType<typeof generateMalwareReport>> | Awaited<ReturnType<typeof generateTechniqueReport>> | Awaited<ReturnType<typeof generateCategoryReport>> = null;

  if (type === "actor") data = await generateActorReport(id);
  else if (type === "malware") data = await generateMalwareReport(id);
  else if (type === "technique") data = await generateTechniqueReport(id);
  else if (type === "category") data = await generateCategoryReport(id);

  if (!data) notFound();

  const jsonString = JSON.stringify(data, null, 2);
  const markdownString = reportToMarkdown(data as never);
  const reportTitle =
    data.reportType === "actor" ? data.actor.name
    : data.reportType === "malware" ? data.malware.name
    : data.reportType === "technique" ? data.technique.name
    : data.category.name;

  if (format === "json") {
    return (
      <div className="max-w-7xl mx-auto space-y-6">
        <style dangerouslySetInnerHTML={{ __html: PRINT_STYLES }} />
        <div className="flex items-center justify-between">
          <div>
            <Link href="/reports" className="text-sm text-[var(--text-secondary)] hover:underline">← Reports</Link>
            <h1 className="text-2xl font-bold mt-1">{reportTitle} — JSON Export</h1>
          </div>
          <ReportActions jsonData={jsonString} markdownData={markdownString} reportTitle={reportTitle} />
        </div>
        <div className="card">
          <pre className="code-block text-xs overflow-auto max-h-[80vh]">{jsonString}</pre>
        </div>
      </div>
    );
  }

  if (format === "md") {
    return (
      <div className="max-w-7xl mx-auto space-y-6">
        <style dangerouslySetInnerHTML={{ __html: PRINT_STYLES }} />
        <div className="flex items-center justify-between">
          <div>
            <Link href="/reports" className="text-sm text-[var(--text-secondary)] hover:underline">← Reports</Link>
            <h1 className="text-2xl font-bold mt-1">{reportTitle} — Markdown Export</h1>
          </div>
          <ReportActions jsonData={jsonString} markdownData={markdownString} reportTitle={reportTitle} />
        </div>
        <div className="card">
          <pre className="code-block text-xs overflow-auto max-h-[80vh] whitespace-pre-wrap">{markdownString}</pre>
        </div>
      </div>
    );
  }

  const genDate = new Date(data.generatedAt).toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <style dangerouslySetInnerHTML={{ __html: PRINT_STYLES }} />

      <div className="flex items-center justify-between no-print">
        <Link href="/reports" className="text-sm text-[var(--text-secondary)] hover:underline">← Reports</Link>
        <div className="flex gap-2">
          <Link
            href={`/reports/${type}/${id}?format=json`}
            className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
          >
            View JSON
          </Link>
          <Link
            href={`/reports/${type}/${id}?format=md`}
            className="px-4 py-2 bg-[var(--bg-tertiary)] border border-[var(--border)] text-[var(--text-primary)] rounded-lg text-sm font-medium hover:bg-[var(--bg-secondary)] transition-colors"
          >
            View MD
          </Link>
          <ReportActions jsonData={jsonString} markdownData={markdownString} reportTitle={reportTitle} />
        </div>
      </div>

      <div className="card">
        <div className="text-center border-b border-[var(--border)] pb-4 mb-4">
          <div className="text-xs font-bold tracking-widest text-[var(--text-secondary)] mb-2">UNCLASSIFIED</div>
          <h1 className="text-2xl font-bold tracking-tight">THREAT INTELLIGENCE REPORT</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">Generated: {genDate}</p>
        </div>

        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-[var(--text-secondary)]">Report Type:</span>
            <span className="ml-2 font-medium capitalize">{data.reportType}</span>
          </div>
          <div>
            <span className="text-[var(--text-secondary)]">Subject:</span>
            <span className="ml-2 font-medium">{reportTitle}</span>
          </div>
          <div>
            <span className="text-[var(--text-secondary)]">Classification:</span>
            <span className="ml-2 font-medium">UNCLASSIFIED</span>
          </div>
        </div>
      </div>

      {data.reportType === "actor" && <ActorReport data={data} />}
      {data.reportType === "malware" && <MalwareReport data={data} />}
      {data.reportType === "technique" && <TechniqueReport data={data} />}
      {data.reportType === "category" && <CategoryReport data={data} />}
    </div>
  );
}

function CoverageBar({ value, label }: { value: number; label: string }) {
  const color = value >= 70 ? "bg-green-500" : value >= 40 ? "bg-amber-500" : "bg-red-500";
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-[var(--text-secondary)]">{label}</span>
        <span className="font-medium">{value}%</span>
      </div>
      <div className="h-2 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

function ActorReport({ data }: { data: NonNullable<Awaited<ReturnType<typeof generateActorReport>>> }) {
  const { actor, techniques, malware, campaigns, atomicTests, detectionRules, coverage, executiveSummary, mitigations, yaraRules, relatedIOCs } = data;

  const gaps = techniques.filter((t) => !t.hasDetections);

  return (
    <>
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Executive Summary</h2>
        <div className="flex gap-3 flex-wrap mb-3">
          <span className="font-mono text-sm text-[var(--accent)]">{actor.externalId}</span>
          {actor.country && <span className="badge bg-zinc-800 text-zinc-300">{actor.country}</span>}
          {actor.motivations.map((m) => (
            <span key={m} className="badge bg-amber-900/30 text-amber-400">{m}</span>
          ))}
          {actor.categories.map((c) => (
            <span key={c.slug} className="badge bg-blue-900/30 text-blue-400">{c.name}</span>
          ))}
        </div>
        <p className="text-sm leading-relaxed mb-3">{executiveSummary}</p>
        <details>
          <summary className="text-xs text-[var(--text-secondary)] cursor-pointer hover:text-[var(--text-primary)]">Full description</summary>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-line mt-2">{actor.description}</p>
        </details>
        {actor.aliases.length > 0 && (
          <div className="mt-3">
            <span className="text-xs text-[var(--text-secondary)]">Also known as: </span>
            {actor.aliases.map((a) => (
              <span key={a} className="badge bg-zinc-800 text-zinc-400 mr-1">{a}</span>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Techniques", value: coverage.totalTechniques },
          { label: "Malware Tools", value: malware.length },
          { label: "Campaigns", value: campaigns.length },
          { label: "Atomic Tests", value: atomicTests.length },
        ].map((s) => (
          <div key={s.label} className="card text-center">
            <div className="text-2xl font-bold text-[var(--accent)]">{s.value}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Coverage Assessment</h2>
        <div className="space-y-3">
          <CoverageBar value={coverage.detectionCoverage} label="Detection Rule Coverage" />
          <CoverageBar value={coverage.testCoverage} label="Atomic Test Coverage" />
        </div>
        <div className="mt-3 text-xs text-[var(--text-secondary)]">
          {coverage.techniquesWithDetections} of {coverage.totalTechniques} techniques have detection rules.{" "}
          {coverage.techniquesWithTests} of {coverage.totalTechniques} have atomic tests.
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Techniques Used ({techniques.length})</h2>
        <div className="space-y-1">
          {techniques.map((t) => (
            <Link
              key={t.id}
              href={`/techniques/${t.id}`}
              className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-[var(--accent)] w-24">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {t.hasTests && <span className="badge bg-green-900/30 text-green-400 text-[10px]">tests</span>}
                {t.hasDetections && <span className="badge bg-blue-900/30 text-blue-400 text-[10px]">detects</span>}
                {!t.hasDetections && <span className="badge bg-red-900/30 text-red-400 text-[10px]">no detect</span>}
                <span className="text-xs text-[var(--text-secondary)]">{t.count}x</span>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {malware.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Associated Malware ({malware.length})</h2>
          <div className="space-y-1">
            {malware.map((m) => (
              <Link key={m.id} href={`/malware/${m.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)]">{m.externalId}</span>
                <span className="text-sm">{m.name}</span>
                {m.type && <span className="badge bg-zinc-800 text-zinc-400">{m.type}</span>}
              </Link>
            ))}
          </div>
        </div>
      )}

      {campaigns.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Campaigns ({campaigns.length})</h2>
          <div className="space-y-2">
            {campaigns.map((c) => (
              <div key={c.id} className="p-3 border border-[var(--border)] rounded-lg">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{c.name}</span>
                  <span className="text-xs text-[var(--text-secondary)]">
                    {c.firstSeen && new Date(c.firstSeen).toLocaleDateString()}
                    {c.lastSeen && ` — ${new Date(c.lastSeen).toLocaleDateString()}`}
                  </span>
                </div>
                {c.description && <p className="text-xs text-[var(--text-secondary)] mt-1 line-clamp-2">{c.description}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      {gaps.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3 text-red-400">Detection Gaps ({gaps.length})</h2>
          <p className="text-sm text-[var(--text-secondary)] mb-3">
            The following techniques have no associated detection rules and represent coverage gaps.
          </p>
          <div className="space-y-1">
            {gaps.map((t) => (
              <Link
                key={t.id}
                href={`/techniques/${t.id}`}
                className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]"
              >
                <span className="font-mono text-sm text-[var(--accent)] w-24">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
                <div className="flex gap-1">
                  {t.tactics.map((tac) => (
                    <span key={tac} className="badge bg-zinc-800 text-zinc-400 text-[10px]">{tac}</span>
                  ))}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {detectionRules.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Detection Rules ({detectionRules.length})</h2>
          <div className="space-y-1">
            {detectionRules.map((r) => (
              <div key={r.id} className="flex items-center justify-between p-2 border border-[var(--border)] rounded">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium">{r.name}</span>
                  {r.technique && <span className="font-mono text-xs text-[var(--accent)]">{r.technique.externalId}</span>}
                </div>
                <div className="flex gap-2">
                  {r.severity && <span className="badge bg-zinc-800 text-zinc-400">{r.severity}</span>}
                  <span className="badge bg-blue-900/30 text-blue-400">{r.language}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {yaraRules.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">YARA Rules ({yaraRules.length})</h2>
          <div className="space-y-1">
            {yaraRules.map((r) => (
              <Link key={r.id} href={`/yara/${r.id}`} className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium">{r.name}</span>
                  {r.malware && <span className="badge bg-purple-900/30 text-purple-400">{r.malware.name}</span>}
                </div>
                <div className="flex gap-2">
                  {r.severity && <span className="badge bg-zinc-800 text-zinc-400">{r.severity}</span>}
                  {r.category && <span className="badge bg-zinc-800 text-zinc-400">{r.category}</span>}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {relatedIOCs.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Related IOCs ({relatedIOCs.length})</h2>
          <div className="space-y-1">
            {relatedIOCs.map((ioc) => (
              <div key={ioc.id} className="flex items-center justify-between p-2 border border-[var(--border)] rounded">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="badge bg-zinc-800 text-zinc-400 shrink-0">{ioc.type}</span>
                  <code className="text-xs text-[var(--accent)] font-mono truncate">{ioc.value}</code>
                </div>
                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 ml-2">{ioc.source}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Recommended Mitigations</h2>
        <ul className="space-y-2 text-sm text-[var(--text-secondary)]">
          {mitigations.map((m, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-blue-400 shrink-0">→</span>
              <span>{m}</span>
            </li>
          ))}
          <li className="flex gap-2">
            <span className="text-blue-400 shrink-0">→</span>
            <span>Review the MITRE ATT&CK page: <a href={actor.url} className="text-[var(--accent)] underline" target="_blank" rel="noopener noreferrer">{actor.url}</a></span>
          </li>
        </ul>
      </div>

      <div className="card page-break">
        <h2 className="text-lg font-semibold mb-3">Appendix: Technique IDs</h2>
        <div className="flex flex-wrap gap-2">
          {techniques.map((t) => (
            <span key={t.id} className="font-mono text-xs badge bg-zinc-800 text-zinc-300">{t.externalId}</span>
          ))}
        </div>
      </div>
    </>
  );
}

function MalwareReport({ data }: { data: NonNullable<Awaited<ReturnType<typeof generateMalwareReport>>> }) {
  const { malware, techniques, actors, atomicTests, detectionRules, coverage, executiveSummary, mitigations, yaraRules, relatedIOCs } = data;
  const gaps = techniques.filter((t) => !t.hasDetections);

  return (
    <>
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Executive Summary</h2>
        <div className="flex gap-3 flex-wrap mb-3">
          <span className="font-mono text-sm text-[var(--accent)]">{malware.externalId}</span>
          {malware.type && <span className="badge bg-zinc-800 text-zinc-300">{malware.type}</span>}
          {malware.platforms.map((p) => (
            <span key={p} className="badge bg-blue-900/30 text-blue-400">{p}</span>
          ))}
        </div>
        <p className="text-sm leading-relaxed mb-3">{executiveSummary}</p>
        <details>
          <summary className="text-xs text-[var(--text-secondary)] cursor-pointer hover:text-[var(--text-primary)]">Full description</summary>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-line mt-2">{malware.description}</p>
        </details>
        {malware.aliases.length > 0 && (
          <div className="mt-3">
            <span className="text-xs text-[var(--text-secondary)]">Also known as: </span>
            {malware.aliases.map((a) => (
              <span key={a} className="badge bg-zinc-800 text-zinc-400 mr-1">{a}</span>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Techniques", value: coverage.totalTechniques },
          { label: "Associated Actors", value: actors.length },
          { label: "Atomic Tests", value: atomicTests.length },
          { label: "Detection Rules", value: detectionRules.length },
        ].map((s) => (
          <div key={s.label} className="card text-center">
            <div className="text-2xl font-bold text-[var(--accent)]">{s.value}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Coverage Assessment</h2>
        <div className="space-y-3">
          <CoverageBar value={coverage.detectionCoverage} label="Detection Rule Coverage" />
          <CoverageBar value={coverage.testCoverage} label="Atomic Test Coverage" />
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Techniques Used ({techniques.length})</h2>
        <div className="space-y-1">
          {techniques.map((t) => (
            <Link
              key={t.id}
              href={`/techniques/${t.id}`}
              className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-sm text-[var(--accent)] w-24">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
              </div>
              <div className="flex items-center gap-2">
                {t.hasTests && <span className="badge bg-green-900/30 text-green-400 text-[10px]">tests</span>}
                {t.hasDetections ? (
                  <span className="badge bg-blue-900/30 text-blue-400 text-[10px]">detects</span>
                ) : (
                  <span className="badge bg-red-900/30 text-red-400 text-[10px]">no detect</span>
                )}
              </div>
            </Link>
          ))}
        </div>
      </div>

      {actors.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Associated Threat Actors ({actors.length})</h2>
          <div className="space-y-1">
            {actors.map((a) => (
              <Link key={a.id} href={`/actors/${a.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)]">{a.externalId}</span>
                <span className="text-sm">{a.name}</span>
                {a.country && <span className="badge bg-zinc-800 text-zinc-400">{a.country}</span>}
              </Link>
            ))}
          </div>
        </div>
      )}

      {gaps.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3 text-red-400">Detection Gaps ({gaps.length})</h2>
          <div className="space-y-1">
            {gaps.map((t) => (
              <Link key={t.id} href={`/techniques/${t.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)] w-24">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {detectionRules.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Detection Rules ({detectionRules.length})</h2>
          <div className="space-y-1">
            {detectionRules.map((r) => (
              <div key={r.id} className="flex items-center justify-between p-2 border border-[var(--border)] rounded">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-medium">{r.name}</span>
                  {r.technique && <span className="font-mono text-xs text-[var(--accent)]">{r.technique.externalId}</span>}
                </div>
                <div className="flex gap-2">
                  {r.severity && <span className="badge bg-zinc-800 text-zinc-400">{r.severity}</span>}
                  <span className="badge bg-blue-900/30 text-blue-400">{r.language}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {yaraRules.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">YARA Rules ({yaraRules.length})</h2>
          <div className="space-y-1">
            {yaraRules.map((r) => (
              <Link key={r.id} href={`/yara/${r.id}`} className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="text-sm font-medium">{r.name}</span>
                <div className="flex gap-2">
                  {r.severity && <span className="badge bg-zinc-800 text-zinc-400">{r.severity}</span>}
                  {r.category && <span className="badge bg-zinc-800 text-zinc-400">{r.category}</span>}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {relatedIOCs.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Related IOCs ({relatedIOCs.length})</h2>
          <div className="space-y-1">
            {relatedIOCs.map((ioc) => (
              <div key={ioc.id} className="flex items-center justify-between p-2 border border-[var(--border)] rounded">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="badge bg-zinc-800 text-zinc-400 shrink-0">{ioc.type}</span>
                  <code className="text-xs text-[var(--accent)] font-mono truncate">{ioc.value}</code>
                </div>
                <span className="text-[10px] text-[var(--text-secondary)] shrink-0 ml-2">{ioc.source}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Recommended Mitigations</h2>
        <ul className="space-y-2 text-sm text-[var(--text-secondary)]">
          {mitigations.map((m, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-blue-400 shrink-0">→</span>
              <span>{m}</span>
            </li>
          ))}
          <li className="flex gap-2">
            <span className="text-blue-400 shrink-0">→</span>
            <span>Review the MITRE ATT&CK page: <a href={malware.url} className="text-[var(--accent)] underline" target="_blank" rel="noopener noreferrer">{malware.url}</a></span>
          </li>
        </ul>
      </div>

      <div className="card page-break">
        <h2 className="text-lg font-semibold mb-3">Appendix: Technique IDs</h2>
        <div className="flex flex-wrap gap-2">
          {techniques.map((t) => (
            <span key={t.id} className="font-mono text-xs badge bg-zinc-800 text-zinc-300">{t.externalId}</span>
          ))}
        </div>
      </div>
    </>
  );
}

function TechniqueReport({ data }: { data: NonNullable<Awaited<ReturnType<typeof generateTechniqueReport>>> }) {
  const { technique, procedures, atomicTests, detectionRules, coverage } = data;

  const actorCount = procedures.filter((p) => p.actor).length;
  const malwareCount = procedures.filter((p) => p.malware).length;

  return (
    <>
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Executive Summary</h2>
        <div className="flex gap-3 flex-wrap mb-3">
          <span className="font-mono text-sm text-[var(--accent)]">{technique.externalId}</span>
          {technique.tactics.map((t) => (
            <span key={t.id} className="badge bg-purple-900/30 text-purple-400">{t.name}</span>
          ))}
          {technique.platforms.map((p) => (
            <span key={p} className="badge bg-blue-900/30 text-blue-400">{p}</span>
          ))}
          {technique.isSubtechnique && <span className="badge bg-zinc-800 text-zinc-400">sub-technique</span>}
        </div>
        {technique.parent && (
          <div className="mb-3">
            <span className="text-xs text-[var(--text-secondary)]">Parent: </span>
            <Link href={`/techniques/${technique.parent.id}`} className="text-sm text-[var(--accent)] hover:underline">
              {technique.parent.externalId} — {technique.parent.name}
            </Link>
          </div>
        )}
        <p className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-line line-clamp-6">{technique.description}</p>
        {technique.categories.length > 0 && (
          <div className="mt-3 flex gap-2 flex-wrap">
            {technique.categories.map((c) => (
              <span key={c.slug} className="badge" style={{ background: `${c.color}20`, color: c.color ?? undefined }}>{c.name}</span>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Procedures", value: coverage.procedureCount },
          { label: "Atomic Tests", value: coverage.atomicTestCount },
          { label: "Detection Rules", value: coverage.detectionRuleCount },
        ].map((s) => (
          <div key={s.label} className="card text-center">
            <div className="text-2xl font-bold text-[var(--accent)]">{s.value}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {technique.detection && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Detection Guidance</h2>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-line">{technique.detection}</p>
        </div>
      )}

      {technique.children.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Sub-Techniques ({technique.children.length})</h2>
          <div className="space-y-1">
            {technique.children.map((c) => (
              <Link key={c.id} href={`/techniques/${c.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)] w-24">{c.externalId}</span>
                <span className="text-sm">{c.name}</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {procedures.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">
            Who Uses This Technique ({procedures.length})
            <span className="text-sm font-normal text-[var(--text-secondary)] ml-2">{actorCount} actors, {malwareCount} malware</span>
          </h2>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {procedures.map((p) => (
              <div key={p.id} className="p-3 border border-[var(--border)] rounded-lg">
                <div className="flex gap-2 mb-1">
                  {p.actor && (
                    <Link href={`/actors/${p.actor.id}`} className="badge bg-red-900/30 text-red-400 hover:opacity-80">{p.actor.name}</Link>
                  )}
                  {p.malware && (
                    <Link href={`/malware/${p.malware.id}`} className="badge bg-orange-900/30 text-orange-400 hover:opacity-80">{p.malware.name}</Link>
                  )}
                  {p.tool && (
                    <span className="badge bg-zinc-800 text-zinc-400">{p.tool.name}</span>
                  )}
                  {p.campaign && (
                    <span className="badge bg-purple-900/30 text-purple-400">{p.campaign.name}</span>
                  )}
                </div>
                <p className="text-xs text-[var(--text-secondary)] line-clamp-2">{p.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {atomicTests.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Atomic Tests ({atomicTests.length})</h2>
          <div className="space-y-3">
            {atomicTests.map((t) => (
              <div key={t.id} className="border border-[var(--border)] rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <Link href={`/commands/${t.id}`} className="text-sm font-medium hover:text-[var(--accent)]">{t.name}</Link>
                  <div className="flex gap-2">
                    <span className="badge bg-zinc-800 text-zinc-400">{t.executor}</span>
                    {t.elevationRequired && <span className="badge bg-red-900/50 text-red-400">elevated</span>}
                  </div>
                </div>
                <div className="flex gap-1 mb-2">
                  {t.platforms.map((p) => (
                    <span key={p} className="badge bg-zinc-800 text-zinc-400 text-[10px]">{p}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {detectionRules.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3">Detection Rules ({detectionRules.length})</h2>
          <div className="space-y-1">
            {detectionRules.map((r) => (
              <div key={r.id} className="flex items-center justify-between p-2 border border-[var(--border)] rounded">
                <span className="text-sm font-medium">{r.name}</span>
                <div className="flex gap-2">
                  {r.severity && <span className="badge bg-zinc-800 text-zinc-400">{r.severity}</span>}
                  <span className="badge bg-blue-900/30 text-blue-400">{r.language}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Recommendations</h2>
        <ul className="space-y-2 text-sm text-[var(--text-secondary)]">
          {coverage.detectionRuleCount === 0 && (
            <li className="flex gap-2">
              <span className="text-red-400 shrink-0">!</span>
              <span>No detection rules exist for this technique. Creating SIEM detections should be a priority.</span>
            </li>
          )}
          {coverage.atomicTestCount === 0 && (
            <li className="flex gap-2">
              <span className="text-amber-400 shrink-0">!</span>
              <span>No atomic tests are linked to this technique. Consider developing custom red team exercises.</span>
            </li>
          )}
          <li className="flex gap-2">
            <span className="text-blue-400 shrink-0">→</span>
            <span>Review the MITRE ATT&CK page: <a href={technique.url} className="text-[var(--accent)] underline" target="_blank" rel="noopener noreferrer">{technique.url}</a></span>
          </li>
        </ul>
      </div>
    </>
  );
}

function CategoryReport({ data }: { data: NonNullable<Awaited<ReturnType<typeof generateCategoryReport>>> }) {
  const { category, techniques, actors, coverage } = data;
  const gaps = techniques.filter((t) => t.detectionCount === 0);

  return (
    <>
      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Executive Summary</h2>
        <div className="flex items-center gap-3 mb-3">
          <span className="w-4 h-4 rounded-full shrink-0" style={{ background: category.color ?? "#666" }} />
          <span className="text-lg font-semibold">{category.name}</span>
        </div>
        {category.description && (
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{category.description}</p>
        )}
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Techniques", value: coverage.totalTechniques },
          { label: "Threat Actors", value: actors.length },
          { label: "w/ Detection", value: coverage.techniquesWithDetections },
          { label: "w/ Atomic Tests", value: coverage.techniquesWithTests },
        ].map((s) => (
          <div key={s.label} className="card text-center">
            <div className="text-2xl font-bold text-[var(--accent)]">{s.value}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Coverage Assessment</h2>
        <div className="space-y-3">
          <CoverageBar value={coverage.detectionCoverage} label="Detection Rule Coverage" />
          <CoverageBar value={coverage.testCoverage} label="Atomic Test Coverage" />
        </div>
        <div className="mt-3 text-xs text-[var(--text-secondary)]">
          {coverage.techniquesWithoutDetections} of {coverage.totalTechniques} techniques lack detection rules.
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Techniques ({techniques.length})</h2>
        <div className="space-y-1 max-h-[60vh] overflow-y-auto">
          {techniques.map((t) => (
            <Link
              key={t.id}
              href={`/techniques/${t.id}`}
              className="flex items-center justify-between p-2 rounded hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs text-[var(--accent)] w-20">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
                {t.isSubtechnique && <span className="text-[9px] text-[var(--text-secondary)]">sub</span>}
              </div>
              <div className="flex gap-2 text-xs">
                <span className="text-[var(--text-secondary)]">{t.procedureCount} proc</span>
                {t.atomicTestCount > 0 && <span className="badge bg-green-900/30 text-green-400 text-[10px]">tests</span>}
                {t.detectionCount > 0 ? (
                  <span className="badge bg-blue-900/30 text-blue-400 text-[10px]">detects</span>
                ) : (
                  <span className="badge bg-red-900/30 text-red-400 text-[10px]">no detect</span>
                )}
              </div>
            </Link>
          ))}
        </div>
      </div>

      {actors.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Threat Actors ({actors.length})</h2>
          <div className="space-y-1">
            {actors.map((a) => (
              <Link key={a.id} href={`/actors/${a.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)]">{a.externalId}</span>
                <span className="text-sm">{a.name}</span>
                {a.country && <span className="badge bg-zinc-800 text-zinc-400">{a.country}</span>}
                <span className="text-xs text-[var(--text-secondary)] ml-auto">{a.procedureCount} procedures</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {gaps.length > 0 && (
        <div className="card page-break">
          <h2 className="text-lg font-semibold mb-3 text-red-400">Detection Gaps ({gaps.length})</h2>
          <p className="text-sm text-[var(--text-secondary)] mb-3">These techniques in this category have no detection rules.</p>
          <div className="space-y-1">
            {gaps.map((t) => (
              <Link key={t.id} href={`/techniques/${t.id}`} className="flex items-center gap-3 p-2 rounded hover:bg-[var(--bg-tertiary)]">
                <span className="font-mono text-sm text-[var(--accent)] w-24">{t.externalId}</span>
                <span className="text-sm">{t.name}</span>
                <span className="text-xs text-[var(--text-secondary)] ml-auto">{t.procedureCount} procedures</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Recommendations</h2>
        <ul className="space-y-2 text-sm text-[var(--text-secondary)]">
          {coverage.detectionCoverage < 50 && (
            <li className="flex gap-2">
              <span className="text-red-400 shrink-0">!</span>
              <span>Detection coverage is below 50% for this category. Focus on high-procedure-count techniques first.</span>
            </li>
          )}
          {coverage.testCoverage < 50 && (
            <li className="flex gap-2">
              <span className="text-amber-400 shrink-0">!</span>
              <span>Less than half of techniques have atomic tests available. Develop or source red team exercises for untested techniques.</span>
            </li>
          )}
          <li className="flex gap-2">
            <span className="text-blue-400 shrink-0">→</span>
            <span>Sort techniques by procedure count and prioritize detection rule creation for high-frequency techniques without coverage.</span>
          </li>
        </ul>
      </div>
    </>
  );
}
