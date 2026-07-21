import { getYaraRules, getYaraStats } from "@/actions/yara";
import Link from "next/link";
import { CopyButton } from "./CopyButton";
import { ExportButton } from "./ExportButton";
import { YaraImport } from "@/components/import/YaraImport";

const CAT_STYLES: Record<string, string> = {
  ransomware: "bg-red-900/50 text-red-400",
  rat: "bg-purple-900/50 text-purple-400",
  stealer: "bg-amber-900/50 text-amber-400",
  "apt-tool": "bg-cyan-900/50 text-cyan-400",
  packer: "bg-zinc-700 text-zinc-300",
  webshell: "bg-orange-900/50 text-orange-400",
  malware: "bg-rose-900/50 text-rose-400",
  "exploit-kit": "bg-pink-900/50 text-pink-400",
  cve: "bg-red-900/50 text-red-300",
  maldoc: "bg-yellow-900/50 text-yellow-400",
  evasion: "bg-indigo-900/50 text-indigo-400",
  capability: "bg-teal-900/50 text-teal-400",
  crypto: "bg-emerald-900/50 text-emerald-400",
};

const CAT_LABELS: Record<string, string> = {
  ransomware: "Ransomware",
  rat: "RAT",
  stealer: "Stealer",
  "apt-tool": "APT Tool",
  packer: "Packer",
  webshell: "Webshell",
  malware: "Malware",
  "exploit-kit": "Exploit Kit",
  cve: "CVE",
  maldoc: "Maldoc",
  evasion: "Evasion",
  capability: "Capability",
  crypto: "Crypto",
};

const SEV_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-zinc-800 text-zinc-400",
};

const CATEGORIES = ["malware", "ransomware", "rat", "stealer", "apt-tool", "webshell", "exploit-kit", "maldoc", "evasion", "packer", "cve", "capability", "crypto"];

export default async function YaraPage(props: {
  searchParams: Promise<{
    page?: string;
    search?: string;
    category?: string;
    severity?: string;
  }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;

  const [{ rules, total, pages }, stats] = await Promise.all([
    getYaraRules({
      page,
      search: searchParams.search,
      category: searchParams.category,
      severity: searchParams.severity,
    }),
    getYaraStats(),
  ]);

  const activeCategory = searchParams.category ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      category: searchParams.category ?? "",
      severity: searchParams.severity ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/yara?${params.toString()}`;
  }

  const exportFilename = activeCategory
    ? `ti-rex-yara-${activeCategory}.yar`
    : "ti-rex-yara-rules.yar";

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">YARA Rule Library</h1>
          <p className="text-sm text-[var(--text-secondary)]">
            {total} rules — mapped to malware families and ATT&CK techniques
          </p>
        </div>
        <ExportButton category={activeCategory || undefined} filename={exportFilename} />
      </div>

      <div className="grid grid-cols-4 md:grid-cols-7 gap-2">
        {stats.byCategory.map((c) => (
          <Link
            key={c.name}
            href={buildUrl({ category: activeCategory === c.name ? "" : c.name })}
            className={`stat-card hover:border-[var(--accent)] transition-colors cursor-pointer ${
              activeCategory === c.name ? "border-[var(--accent)]" : ""
            }`}
          >
            <div className="stat-value text-lg">{c.count}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{CAT_LABELS[c.name] ?? c.name}</div>
          </Link>
        ))}
      </div>

      <div className="flex gap-2 flex-wrap">
        <Link
          href={buildUrl({ category: "" })}
          className={`px-3 py-1.5 rounded-lg text-sm ${
            !activeCategory
              ? "bg-[var(--accent)] text-white"
              : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
          }`}
        >
          All ({stats.total})
        </Link>
        {CATEGORIES.map((c) => {
          const count = stats.byCategory.find((s) => s.name === c)?.count ?? 0;
          return (
            <Link
              key={c}
              href={buildUrl({ category: activeCategory === c ? "" : c })}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                activeCategory === c
                  ? "bg-[var(--accent)] text-white"
                  : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {CAT_LABELS[c]} ({count})
            </Link>
          );
        })}
      </div>

      <YaraImport />

      <form className="flex gap-3 flex-wrap" action="/yara">
        <input type="hidden" name="category" value={activeCategory} />
        <input
          type="search"
          name="search"
          placeholder="Search rules... (e.g. LockBit, beacon, mimikatz)"
          defaultValue={searchParams.search ?? ""}
          className="flex-1 min-w-[250px]"
        />
        <select name="severity" defaultValue={searchParams.severity ?? ""}>
          <option value="">All severities</option>
          {stats.bySeverity.filter((s) => s.name).map((s) => (
            <option key={s.name} value={s.name!}>
              {s.name} ({s.count})
            </option>
          ))}
        </select>
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">
          Filter
        </button>
      </form>

      <div className="space-y-4">
        {rules.map((r) => (
          <div key={r.id} className="card">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="min-w-0 flex-1">
                <Link
                  href={`/yara/${r.id}`}
                  className="text-sm font-semibold hover:text-[var(--accent)] transition-colors"
                >
                  {r.name}
                </Link>
                <div className="flex gap-2 mt-1 flex-wrap">
                  {r.malware && (
                    <Link href={`/malware/${r.malware.id}`}>
                      <span className="badge bg-red-900/20 text-red-400 hover:bg-red-900/40 transition-colors">
                        {r.malware.name}
                      </span>
                    </Link>
                  )}
                  {r.technique && (
                    <Link href={`/techniques/${r.technique.id}`}>
                      <span className="badge bg-blue-900/20 text-blue-400 hover:bg-blue-900/40 transition-colors">
                        {r.technique.externalId} — {r.technique.name}
                      </span>
                    </Link>
                  )}
                </div>
              </div>
              <div className="flex gap-2 shrink-0 flex-wrap justify-end">
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
            </div>

            {r.description && (
              <p className="text-xs text-[var(--text-secondary)] mb-3">{r.description}</p>
            )}

            <pre className="code-block">{r.rule}</pre>

            <div className="flex items-center justify-between mt-3">
              <div className="text-[10px] text-[var(--text-secondary)]">
                {r.author && <span>{r.author}</span>}
                {r.reference && (
                  <>
                    {" · "}
                    <a
                      href={r.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:text-[var(--accent)]"
                    >
                      Reference
                    </a>
                  </>
                )}
              </div>
              <div className="flex gap-2">
                <CopyButton text={r.rule} label="Copy Rule" />
                <Link
                  href={`/yara/${r.id}`}
                  className="px-3 py-1.5 text-xs rounded-lg bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors border border-[var(--border)]"
                >
                  Details
                </Link>
              </div>
            </div>
          </div>
        ))}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Prev
            </Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">
            Page {page} of {pages}
          </span>
          {page < pages && (
            <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">
              Next
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
