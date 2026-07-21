import { generateSigmaForTest } from "@/actions/sigma";
import { analyzeCommand } from "@/lib/sigma-generator";
import { notFound } from "next/navigation";
import Link from "next/link";
import { CopySigmaButton } from "../CopySigmaButton";

const LEVEL_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
};

const EXECUTOR_STYLES: Record<string, string> = {
  powershell: "bg-blue-900/50 text-blue-400",
  command_prompt: "bg-orange-900/50 text-orange-400",
  bash: "bg-green-900/50 text-green-400",
  sh: "bg-green-900/30 text-green-300",
};

export default async function SigmaDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const test = await generateSigmaForTest(id);
  if (!test) notFound();

  const analysis = analyzeCommand({
    name: test.name,
    techniqueId: test.technique.externalId,
    description: test.description,
    executor: test.executor,
    command: test.command,
    platforms: test.platforms as unknown as string,
    elevationRequired: test.elevationRequired,
  });

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Link href="/sigma-generator" className="text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]">
            ← Sigma Generator
          </Link>
          <span className="text-xs text-[var(--text-secondary)]">/</span>
          <Link
            href={`/techniques/${test.technique.id}`}
            className="text-xs font-mono text-[var(--accent)] hover:underline"
          >
            {test.technique.externalId}
          </Link>
        </div>
        <h1 className="text-2xl font-bold">{test.name}</h1>
        <div className="flex gap-2 mt-2 flex-wrap">
          <Link
            href={`/techniques/${test.technique.id}`}
            className="text-sm font-mono text-[var(--accent)] hover:underline"
          >
            {test.technique.externalId} — {test.technique.name}
          </Link>
        </div>
        <div className="flex gap-2 mt-2 flex-wrap">
          <span className={`badge ${EXECUTOR_STYLES[test.executor] ?? "bg-zinc-800 text-zinc-400"}`}>
            {test.executor}
          </span>
          <span className={`badge ${LEVEL_STYLES[test.sigmaRule.level] ?? "bg-zinc-800 text-zinc-400"}`}>
            {test.sigmaRule.level}
          </span>
          {test.elevationRequired && (
            <span className="badge bg-red-900/50 text-red-400">requires elevation</span>
          )}
          {(test.platforms as string[]).map((p) => (
            <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
          ))}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)]">{test.description}</p>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-3">Atomic Test Command</h2>
        <pre className="code-block">{test.command}</pre>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Generated Sigma Rule</h2>
          <CopySigmaButton yaml={test.sigmaYaml} />
        </div>
        <pre className="code-block text-green-300">{test.sigmaYaml}</pre>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Detection Breakdown</h2>

        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Executor Mapping</h3>
            <div className="p-3 rounded-lg bg-[var(--bg-tertiary)] text-sm">
              <span className="text-[var(--text-secondary)]">Executor </span>
              <code className={`badge ${EXECUTOR_STYLES[test.executor] ?? "bg-zinc-800 text-zinc-400"}`}>
                {test.executor}
              </code>
              <span className="text-[var(--text-secondary)]"> mapped to executor family </span>
              <code className="text-[var(--accent)]">{analysis.executorFamily}</code>
              {analysis.executorFamily === "powershell" && (
                <span className="text-[var(--text-secondary)]">
                  {" "}→ logsource: <code className="text-zinc-300">process_creation / windows</code>
                  {" "}or <code className="text-zinc-300">windows / powershell</code>
                </span>
              )}
              {analysis.executorFamily === "cmd" && (
                <span className="text-[var(--text-secondary)]">
                  {" "}→ logsource: <code className="text-zinc-300">process_creation / windows</code>
                </span>
              )}
              {analysis.executorFamily === "bash" && (
                <span className="text-[var(--text-secondary)]">
                  {" "}→ logsource: <code className="text-zinc-300">process_creation / linux</code>
                </span>
              )}
            </div>
          </div>

          {analysis.matchedPatterns.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">
                Suspicious Patterns Detected ({analysis.matchedPatterns.length})
              </h3>
              <div className="flex gap-2 flex-wrap">
                {analysis.matchedPatterns.map((p) => (
                  <span key={p} className="badge bg-red-900/30 text-red-400 font-mono">
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {analysis.extractedKeywords.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">
                Extracted Detection Keywords
              </h3>
              <div className="flex gap-2 flex-wrap">
                {analysis.extractedKeywords.map((k) => (
                  <span key={k} className="badge bg-blue-900/30 text-blue-400 font-mono">
                    {k}
                  </span>
                ))}
              </div>
              <p className="text-xs text-[var(--text-secondary)] mt-2">
                These keywords are used to populate the <code className="text-zinc-300">{analysis.selectionField}</code> detection field.
              </p>
            </div>
          )}

          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Severity Level</h3>
            <div className="p-3 rounded-lg bg-[var(--bg-tertiary)] text-sm flex items-center gap-3">
              <span className={`badge ${LEVEL_STYLES[test.sigmaRule.level] ?? "bg-zinc-800 text-zinc-400"}`}>
                {test.sigmaRule.level}
              </span>
              <span className="text-[var(--text-secondary)]">{analysis.levelReason}</span>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">MITRE ATT&CK Tags</h3>
            <div className="flex gap-2 flex-wrap">
              {test.sigmaRule.tags.map((tag) => (
                <span key={tag} className="badge bg-purple-900/30 text-purple-400 font-mono">
                  {tag}
                </span>
              ))}
            </div>
            {analysis.tacticTag && (
              <p className="text-xs text-[var(--text-secondary)] mt-2">
                Tactic <code className="text-zinc-300">{analysis.tacticTag}</code> derived from technique prefix{" "}
                <code className="text-zinc-300">{test.technique.externalId.split(".")[0]}</code>.
              </p>
            )}
          </div>

          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Rule ID</h3>
            <p className="text-xs text-[var(--text-secondary)]">
              Deterministic UUID generated from technique ID + test name via SHA-1 hash:{" "}
              <code className="text-zinc-300 font-mono">{test.sigmaRule.id}</code>
            </p>
          </div>
        </div>
      </div>

      {test.technique.tactics.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-2">Kill Chain Phases</h2>
          <div className="flex gap-2 flex-wrap">
            {test.technique.tactics.map((tt) => (
              <span key={tt.tactic.id} className="badge bg-blue-900/30 text-blue-400">
                {tt.tactic.name}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex gap-3">
        <Link
          href={`/commands/${test.id}`}
          className="px-4 py-2 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] border border-[var(--border)] text-sm rounded-lg transition-colors"
        >
          View full atomic test →
        </Link>
        <Link
          href={`/techniques/${test.technique.id}`}
          className="px-4 py-2 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] border border-[var(--border)] text-sm rounded-lg transition-colors"
        >
          View technique {test.technique.externalId} →
        </Link>
        <Link
          href="/sigma-generator"
          className="px-4 py-2 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] border border-[var(--border)] text-sm rounded-lg transition-colors"
        >
          ← Back to generator
        </Link>
      </div>
    </div>
  );
}
