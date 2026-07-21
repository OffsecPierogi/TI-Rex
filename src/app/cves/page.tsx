import { getCves, getCveStats } from "@/actions/cves";
import Link from "next/link";
import { formatDistanceToNow, format } from "date-fns";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-900/50 text-red-400",
  high: "bg-orange-900/50 text-orange-400",
  medium: "bg-yellow-900/50 text-yellow-400",
  low: "bg-green-900/50 text-green-400",
};

function severityClass(severity: string | null) {
  if (!severity) return "bg-zinc-800 text-zinc-400";
  return SEVERITY_STYLES[severity.toLowerCase()] ?? "bg-zinc-800 text-zinc-400";
}

function epssBadgeClass(score: number | null): string {
  if (score === null || score === undefined) return "bg-zinc-800 text-zinc-400";
  if (score > 0.7) return "bg-red-900/50 text-red-400";
  if (score > 0.3) return "bg-orange-900/50 text-orange-400";
  return "bg-green-900/50 text-green-400";
}

function cvssBadgeClass(score: number | null): string {
  if (score === null || score === undefined) return "bg-zinc-800 text-zinc-400";
  if (score >= 9.0) return "bg-red-900/50 text-red-400";
  if (score >= 7.0) return "bg-orange-900/50 text-orange-400";
  if (score >= 4.0) return "bg-yellow-900/50 text-yellow-400";
  return "bg-green-900/50 text-green-400";
}

export default async function CvesPage(props: {
  searchParams: Promise<{
    page?: string;
    vendor?: string;
    ransomware?: string;
    aptLinked?: string;
    days?: string;
    search?: string;
    sortBy?: string;
    minEpss?: string;
    source?: string;
  }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const days = searchParams.days ? Number(searchParams.days) : 30;
  const sortBy = (searchParams.sortBy as "epss" | "cvss" | "date") || undefined;
  const minEpss = searchParams.minEpss ? Number(searchParams.minEpss) : undefined;
  const source = (searchParams.source as "all" | "kev" | "nvd") || undefined;

  const [{ items, total, pages }, stats] = await Promise.all([
    getCves({
      page,
      search: searchParams.search,
      vendor: searchParams.vendor,
      ransomware: searchParams.ransomware === "true",
      aptLinked: searchParams.aptLinked === "true",
      days,
      sortBy,
      minEpss,
      source,
    }),
    getCveStats(),
  ]);

  const activeVendor = searchParams.vendor ?? "";
  const activeRansomware = searchParams.ransomware ?? "";
  const activeAptLinked = searchParams.aptLinked ?? "";
  const activeDays = searchParams.days ?? "";
  const activeSortBy = searchParams.sortBy ?? "";
  const activeMinEpss = searchParams.minEpss ?? "";
  const activeSource = searchParams.source ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      vendor: searchParams.vendor ?? "",
      ransomware: searchParams.ransomware ?? "",
      aptLinked: searchParams.aptLinked ?? "",
      days: searchParams.days ?? "",
      search: searchParams.search ?? "",
      sortBy: searchParams.sortBy ?? "",
      minEpss: searchParams.minEpss ?? "",
      source: searchParams.source ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/cves?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">CVE / Vulnerability Tracker</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total.toLocaleString()} CVEs — {stats.kevCount.toLocaleString()} from CISA KEV, {(stats.total - stats.kevCount).toLocaleString()} from NVD
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.total.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Total CVEs</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.kevCount.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">CISA KEV</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.last30d.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Last 30 Days</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.last90d.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Last 90 Days</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.aptLinked.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">APT-Linked</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.ransomwareLinked.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Ransomware</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.highEpss.toLocaleString()}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">High EPSS (&gt;0.5)</div>
        </div>
        <div className="stat-card">
          <div className="stat-value text-lg">{stats.avgEpss.toFixed(3)}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Avg EPSS</div>
        </div>
      </div>

      {/* Source filter */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Source:</span>
        {[
          { label: "All CVEs", value: "" },
          { label: "CISA KEV", value: "kev" },
          { label: "NVD", value: "nvd" },
        ].map((s) => (
          <Link key={s.value} href={buildUrl({ source: activeSource === s.value ? "" : s.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeSource === s.value || (!activeSource && !s.value) ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {s.label}
          </Link>
        ))}

        <span className="w-px h-5 bg-[var(--border)] mx-1" />

        <Link href={buildUrl({ aptLinked: activeAptLinked === "true" ? "" : "true" })}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeAptLinked === "true" ? "bg-purple-900/50 text-purple-400 border border-purple-800" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
          APT-Linked
        </Link>

        <Link href={buildUrl({ ransomware: activeRansomware === "true" ? "" : "true" })}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeRansomware === "true" ? "bg-red-900/50 text-red-400 border border-red-800" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
          Ransomware Only
        </Link>
      </div>

      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Time:</span>
        {[
          { label: "7 Days", value: "7" },
          { label: "30 Days", value: "30" },
          { label: "90 Days", value: "90" },
          { label: "6 Months", value: "180" },
          { label: "1 Year", value: "365" },
          { label: "All Time", value: "0" },
        ].map((d) => {
          const isActive = activeDays === d.value || (!activeDays && d.value === "30");
          return (
            <Link key={d.value} href={buildUrl({ days: d.value })}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${isActive ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
              {d.label}
            </Link>
          );
        })}

        <span className="w-px h-5 bg-[var(--border)] mx-1" />

        {stats.topVendors.slice(0, 6).map((v) => (
          <Link key={v.vendor} href={buildUrl({ vendor: activeVendor === v.vendor ? "" : v.vendor })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeVendor === v.vendor ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {v.vendor}
          </Link>
        ))}

        <form className="flex gap-2 ml-auto" action="/cves">
          <input type="hidden" name="source" value={activeSource} />
          <input type="hidden" name="vendor" value={activeVendor} />
          <input type="hidden" name="ransomware" value={activeRansomware} />
          <input type="hidden" name="aptLinked" value={activeAptLinked} />
          <input type="hidden" name="days" value={activeDays} />
          <input type="hidden" name="sortBy" value={activeSortBy} />
          <input type="hidden" name="minEpss" value={activeMinEpss} />
          <input type="search" name="search" placeholder="Search CVEs..." defaultValue={searchParams.search ?? ""} className="min-w-[250px]" />
          <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Search</button>
        </form>
      </div>

      {/* Sort & EPSS controls */}
      <div className="flex gap-2 flex-wrap items-center">
        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Sort:</span>
        {[
          { label: "Date", value: "" },
          { label: "EPSS Score", value: "epss" },
          { label: "CVSS Score", value: "cvss" },
        ].map((s) => (
          <Link key={s.value} href={buildUrl({ sortBy: activeSortBy === s.value ? "" : s.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeSortBy === s.value || (!activeSortBy && !s.value) ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {s.label}
          </Link>
        ))}

        <span className="w-px h-5 bg-[var(--border)] mx-1" />

        <span className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider">Min EPSS:</span>
        {[
          { label: "All", value: "" },
          { label: ">0.1", value: "0.1" },
          { label: ">0.3", value: "0.3" },
          { label: ">0.5", value: "0.5" },
          { label: ">0.7", value: "0.7" },
        ].map((e) => (
          <Link key={e.value} href={buildUrl({ minEpss: activeMinEpss === e.value ? "" : e.value })}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${activeMinEpss === e.value || (!activeMinEpss && !e.value) ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}>
            {e.label}
          </Link>
        ))}
      </div>

      <div className="space-y-3">
        {items.map((item) => {
          const displayDate = item.publishedDate ?? item.dateAdded;
          return (
            <Link key={item.id} href={`/cves/${item.id}`} className="card block">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm text-[var(--accent)] font-semibold">{item.cveId}</span>
                    {displayDate && (
                      <span className="text-xs text-[var(--text-secondary)]">
                        {formatDistanceToNow(displayDate, { addSuffix: true })}
                      </span>
                    )}
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${item.type === "kev" ? "bg-red-900/40 text-red-400" : "bg-blue-900/40 text-blue-400"}`}>
                      {item.type === "kev" ? "KEV" : "NVD"}
                    </span>
                  </div>
                  <div className="text-sm font-semibold leading-snug">
                    {item.type === "NVD" ? item.description.slice(0, 150) + (item.description.length > 150 ? "..." : "") : item.title}
                  </div>
                  <div className="flex items-center gap-2 mt-2 flex-wrap">
                    {item.vendorProject && (
                      <span className="badge bg-blue-900/50 text-blue-400">{item.vendorProject}</span>
                    )}
                    {item.product && (
                      <span className="badge bg-zinc-800 text-zinc-400">{item.product}</span>
                    )}
                    {item.severity && (
                      <span className={`badge ${severityClass(item.severity)}`}>{item.severity}</span>
                    )}
                    {item.knownRansomware && (
                      <span className="badge bg-red-900/50 text-red-400">Ransomware</span>
                    )}
                    {item.actors.length > 0 && item.actors.map((a) => (
                      <span key={a.actor.id} className="badge bg-purple-900/50 text-purple-400">
                        {a.actor.name}{a.actor.country ? ` (${a.actor.country})` : ""}
                      </span>
                    ))}
                    {item.epssScore !== null && item.epssScore !== undefined && (
                      <span className={`badge ${epssBadgeClass(item.epssScore)}`}>
                        EPSS {item.epssScore.toFixed(3)}
                      </span>
                    )}
                    {item.cvssScore !== null && item.cvssScore !== undefined && (
                      <span className={`badge ${cvssBadgeClass(item.cvssScore)}`}>
                        CVSS {item.cvssScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-2">
                    {item.publishedDate && (
                      <span className="text-[10px] text-[var(--text-secondary)]">Published: {format(item.publishedDate, "MMM d, yyyy")}</span>
                    )}
                    {item.dateAdded && (
                      <span className="text-[10px] text-[var(--text-secondary)]">KEV Added: {format(item.dateAdded, "MMM d, yyyy")}</span>
                    )}
                    {item.dueDate && (
                      <span className="text-[10px] text-[var(--text-secondary)]">Remediation Due: {format(item.dueDate, "MMM d, yyyy")}</span>
                    )}
                  </div>
                </div>
              </div>
            </Link>
          );
        })}
        {items.length === 0 && (
          <div className="card text-center text-[var(--text-secondary)] py-12">
            No CVEs found matching your filters.
          </div>
        )}
      </div>

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Prev</Link>}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">Page {page} of {pages}</span>
          {page < pages && <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Next</Link>}
        </div>
      )}
    </div>
  );
}
