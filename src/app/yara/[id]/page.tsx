import { getYaraRuleDetail, getRelatedYaraRules } from "@/actions/yara";
import { notFound } from "next/navigation";
import Link from "next/link";
import { CopyButton } from "../CopyButton";
import { ExportButton } from "../ExportButton";

const CAT_STYLES: Record<string, string> = {
  ransomware: "bg-red-900/50 text-red-400",
  rat: "bg-purple-900/50 text-purple-400",
  stealer: "bg-amber-900/50 text-amber-400",
  "apt-tool": "bg-cyan-900/50 text-cyan-400",
  packer: "bg-zinc-700 text-zinc-300",
  webshell: "bg-orange-900/50 text-orange-400",
};

const CAT_LABELS: Record<string, string> = {
  ransomware: "Ransomware",
  rat: "RAT",
  stealer: "Stealer",
  "apt-tool": "APT Tool",
  packer: "Packer",
  webshell: "Webshell",
};

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-zinc-800 text-zinc-400",
};

export default async function YaraDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const rule = await getYaraRuleDetail(id);
  if (!rule) notFound();

  const related = await getRelatedYaraRules(id, rule.category, rule.malwareId);

  const downloadContent = [
    "/*",
    ` * ${rule.name}`,
    ` * ${rule.description ?? ""}`,
    ` * Author: ${rule.author ?? "TI-Rex"}`,
    ` * Reference: ${rule.reference ?? ""}`,
    " */",
    "",
    rule.rule,
    "",
  ].join("\n");

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <Link href="/yara" className="text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]">
          ← YARA Rule Library
        </Link>
        <div className="flex items-start justify-between gap-3 mt-2">
          <div className="min-w-0 flex-1">
            <div className="flex gap-2 flex-wrap mb-1">
              {rule.severity && (
                <span className={`badge ${SEV_STYLES[rule.severity] ?? "bg-zinc-800 text-zinc-400"}`}>
                  {rule.severity}
                </span>
              )}
              {rule.category && (
                <span className={`badge ${CAT_STYLES[rule.category] ?? "bg-zinc-800 text-zinc-400"}`}>
                  {CAT_LABELS[rule.category] ?? rule.category}
                </span>
              )}
            </div>
            <h1 className="text-xl font-bold font-mono break-all">{rule.name}</h1>
          </div>
          <div className="flex gap-2 shrink-0">
            <CopyButton text={rule.rule} label="Copy Rule" />
            <ExportButton content={downloadContent} filename={`${rule.name}.yar`} />
          </div>
        </div>
      </div>

      {rule.description && (
        <div className="card">
          <h2 className="text-sm font-semibold mb-1 text-[var(--text-secondary)] uppercase tracking-wider">Description</h2>
          <p className="text-sm leading-relaxed">{rule.description}</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rule.malware && (
          <div className="card">
            <h2 className="text-sm font-semibold mb-2 text-[var(--text-secondary)] uppercase tracking-wider">Malware Family</h2>
            <Link
              href={`/malware/${rule.malware.id}`}
              className="flex items-center gap-2 hover:text-[var(--accent)] transition-colors"
            >
              <span className="text-base"></span>
              <div>
                <div className="font-semibold">{rule.malware.name}</div>
                <div className="text-xs font-mono text-[var(--text-secondary)]">{rule.malware.externalId}</div>
              </div>
            </Link>
            {rule.malware.description && (
              <p className="text-xs text-[var(--text-secondary)] mt-2 line-clamp-3">
                {rule.malware.description.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")}
              </p>
            )}
          </div>
        )}

        {rule.technique && (
          <div className="card">
            <h2 className="text-sm font-semibold mb-2 text-[var(--text-secondary)] uppercase tracking-wider">ATT&CK Technique</h2>
            <Link
              href={`/techniques/${rule.technique.id}`}
              className="flex items-center gap-2 hover:text-[var(--accent)] transition-colors"
            >
              <span className="text-base"></span>
              <div>
                <div className="font-semibold">{rule.technique.name}</div>
                <div className="text-xs font-mono text-[var(--text-secondary)]">{rule.technique.externalId}</div>
              </div>
            </Link>
            {rule.technique.description && (
              <p className="text-xs text-[var(--text-secondary)] mt-2 line-clamp-3">
                {rule.technique.description.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").slice(0, 200)}
              </p>
            )}
          </div>
        )}
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">YARA Rule</h2>
          <CopyButton text={rule.rule} label="Copy" />
        </div>
        <pre className="code-block">{rule.rule}</pre>
      </div>

      <div className="card">
        <h2 className="text-sm font-semibold mb-3 text-[var(--text-secondary)] uppercase tracking-wider">Metadata</h2>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
          {rule.author && (
            <>
              <dt className="text-[var(--text-secondary)]">Author</dt>
              <dd>{rule.author}</dd>
            </>
          )}
          {rule.reference && (
            <>
              <dt className="text-[var(--text-secondary)]">Reference</dt>
              <dd>
                <a href={rule.reference} target="_blank" rel="noopener noreferrer" className="text-[var(--accent)] hover:underline break-all">
                  {rule.reference}
                </a>
              </dd>
            </>
          )}
          {rule.tags && (
            <>
              <dt className="text-[var(--text-secondary)]">Tags</dt>
              <dd>
                <div className="flex gap-1.5 flex-wrap">
                  {rule.tags.split(",").map((t) => (
                    <span key={t} className="badge bg-zinc-800 text-zinc-400">{t.trim()}</span>
                  ))}
                </div>
              </dd>
            </>
          )}
          <dt className="text-[var(--text-secondary)]">Created</dt>
          <dd>{new Date(rule.createdAt).toLocaleDateString()}</dd>
        </dl>
      </div>

      {related.length > 0 && (
        <div className="card">
          <h2 className="text-sm font-semibold mb-3 text-[var(--text-secondary)] uppercase tracking-wider">Related Rules</h2>
          <div className="space-y-2">
            {related.map((r) => (
              <Link
                key={r.id}
                href={`/yara/${r.id}`}
                className="flex items-center justify-between p-2.5 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors border border-[var(--border)]"
              >
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-mono truncate">{r.name}</div>
                  {r.description && (
                    <div className="text-xs text-[var(--text-secondary)] truncate">{r.description}</div>
                  )}
                </div>
                <div className="flex gap-2 shrink-0 ml-3">
                  {r.severity && (
                    <span className={`badge ${SEV_STYLES[r.severity] ?? "bg-zinc-800 text-zinc-400"}`}>
                      {r.severity}
                    </span>
                  )}
                  {r.category && (
                    <span className={`badge ${CAT_STYLES[r.category] ?? "bg-zinc-800 text-zinc-400"}`}>
                      {CAT_LABELS[r.category] ?? r.category}
                    </span>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
