import { getAtomicTestsForSigma, getSigmaStats } from "@/actions/sigma";
import Link from "next/link";
import { CopySigmaButton } from "./CopySigmaButton";

const EXECUTOR_PILLS = [
  { label: "All", value: "" },
  { label: "PowerShell", value: "powershell" },
  { label: "CMD", value: "command_prompt" },
  { label: "Bash", value: "bash" },
  { label: "sh", value: "sh" },
];

const PLATFORM_PILLS = [
  { label: "All Platforms", value: "" },
  { label: "Windows", value: "windows" },
  { label: "Linux", value: "linux" },
  { label: "macOS", value: "macos" },
];

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

export default async function SigmaGeneratorPage(props: {
  searchParams: Promise<{ page?: string; search?: string; executor?: string; platform?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;

  const [{ tests, total, pages, executorCounts }, stats] = await Promise.all([
    getAtomicTestsForSigma({
      page,
      search: searchParams.search,
      executor: searchParams.executor,
      platform: searchParams.platform,
    }),
    getSigmaStats(),
  ]);

  const activeExecutor = searchParams.executor ?? "";
  const activePlatform = searchParams.platform ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      executor: searchParams.executor ?? "",
      platform: searchParams.platform ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/sigma-generator?${params.toString()}`;
  }

  const execMap = Object.fromEntries(executorCounts.map((e) => [e.name, e.count]));

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Sigma Rule Generator</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Auto-generating Sigma detection rules from {total.toLocaleString()} Atomic Red Team tests
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="stat-card">
          <div className="stat-value">{stats.total.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)]">Total Tests</div>
        </div>
        {stats.byExecutor.map((e) => (
          <Link
            key={e.name}
            href={buildUrl({ executor: activeExecutor === e.name ? "" : e.name })}
            className={`stat-card hover:border-[var(--accent)] transition-colors cursor-pointer ${
              activeExecutor === e.name ? "border-[var(--accent)]" : ""
            }`}
          >
            <div className="stat-value text-lg">{e.count.toLocaleString()}</div>
            <div className={`text-xs mt-0.5 badge ${EXECUTOR_STYLES[e.name] ?? "bg-zinc-800 text-zinc-400"}`}>
              {e.name}
            </div>
          </Link>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        {EXECUTOR_PILLS.map((p) => (
          <Link
            key={p.value}
            href={buildUrl({ executor: p.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              activeExecutor === p.value
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {p.label}
            {p.value && execMap[p.value] != null ? ` (${execMap[p.value]})` : ""}
          </Link>
        ))}
        <span className="text-[var(--border)] mx-1">|</span>
        {PLATFORM_PILLS.map((p) => (
          <Link
            key={p.value}
            href={buildUrl({ platform: p.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              activePlatform === p.value
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {p.label}
          </Link>
        ))}
      </div>

      <form className="flex gap-3" action="/sigma-generator">
        <input type="hidden" name="executor" value={activeExecutor} />
        <input type="hidden" name="platform" value={activePlatform} />
        <input
          type="search"
          name="search"
          placeholder="Search by technique ID, name, or command..."
          defaultValue={searchParams.search ?? ""}
          className="flex-1"
        />
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">
          Filter
        </button>
      </form>

      <div className="space-y-4">
        {tests.map((t) => (
          <div key={t.id} className="card">
            <div className="flex items-start justify-between mb-3">
              <div>
                <Link
                  href={`/sigma-generator/${t.id}`}
                  className="text-sm font-semibold hover:text-[var(--accent)] transition-colors"
                >
                  {t.name}
                </Link>
                <div className="flex items-center gap-2 mt-1">
                  <Link
                    href={`/techniques/${t.technique.id}`}
                    className="text-xs font-mono text-[var(--accent)] hover:underline"
                  >
                    {t.technique.externalId}
                  </Link>
                  <span className="text-xs text-[var(--text-secondary)]">{t.technique.name}</span>
                </div>
              </div>
              <div className="flex gap-2 shrink-0 flex-wrap justify-end">
                <span className={`badge ${EXECUTOR_STYLES[t.executor] ?? "bg-zinc-800 text-zinc-400"}`}>
                  {t.executor}
                </span>
                <span className={`badge ${LEVEL_STYLES[t.sigmaRule.level] ?? "bg-zinc-800 text-zinc-400"}`}>
                  {t.sigmaRule.level}
                </span>
                {t.elevationRequired && (
                  <span className="badge bg-red-900/50 text-red-400">elevated</span>
                )}
                {t.platforms.map((p) => (
                  <span key={p} className="badge bg-zinc-800 text-zinc-400">{p}</span>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <div className="text-xs text-[var(--text-secondary)] mb-1 font-medium">Command</div>
                <pre className="code-block">{t.command}</pre>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <div className="text-xs text-[var(--text-secondary)] font-medium">Generated Sigma Rule</div>
                  <div className="flex items-center gap-2">
                    <Link
                      href={`/sigma-generator/${t.id}`}
                      className="text-xs text-[var(--accent)] hover:underline"
                    >
                      View breakdown →
                    </Link>
                    <CopySigmaButton yaml={t.sigmaYaml} />
                  </div>
                </div>
                <pre className="code-block text-green-300">{t.sigmaYaml}</pre>
              </div>
            </div>
          </div>
        ))}
      </div>

      {tests.length === 0 && (
        <div className="card text-center py-12">
          <p className="text-[var(--text-secondary)]">No tests match your filters.</p>
        </div>
      )}

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link
              href={buildUrl({ page: String(page - 1) })}
              className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm"
            >
              Prev
            </Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">
            Page {page} of {pages}
          </span>
          {page < pages && (
            <Link
              href={buildUrl({ page: String(page + 1) })}
              className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm"
            >
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
