import { getPurpleTeamCoverage, getPurpleTeamStats } from "@/actions/purple-team";
import Link from "next/link";

const STATUS_DOT: Record<string, string> = {
  gap: "bg-red-500",
  covered: "bg-green-500",
  "detection-only": "bg-blue-500",
};

const STATUS_ROW: Record<string, string> = {
  gap: "bg-red-900/20 border-red-800/40",
  covered: "bg-green-900/10 border-green-900/30",
  "detection-only": "bg-blue-900/10 border-blue-900/30",
};

const STATUS_LABEL: Record<string, string> = {
  gap: "No Detection",
  covered: "Covered",
  "detection-only": "Detection Only",
};

const STATUS_BADGE: Record<string, string> = {
  gap: "bg-red-900/50 text-red-400",
  covered: "bg-green-900/50 text-green-400",
  "detection-only": "bg-blue-900/50 text-blue-400",
};

type Status = "covered" | "gap" | "detection-only";

export default async function PurpleTeamPage(props: {
  searchParams: Promise<{
    search?: string;
    status?: string;
    tactic?: string;
    category?: string;
  }>;
}) {
  const searchParams = await props.searchParams;
  const activeStatus = (searchParams.status as Status | undefined) ?? undefined;
  const activeTactic = searchParams.tactic ?? "";
  const activeCategory = searchParams.category ?? "";

  const [items, stats] = await Promise.all([
    getPurpleTeamCoverage({
      search: searchParams.search,
      status: activeStatus,
      tactic: activeTactic || undefined,
      category: activeCategory || undefined,
    }),
    getPurpleTeamStats(),
  ]);

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      status: searchParams.status ?? "",
      tactic: searchParams.tactic ?? "",
      category: searchParams.category ?? "",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    const qs = params.toString();
    return `/purple-team${qs ? `?${qs}` : ""}`;
  }

  const coverageColor =
    stats.coveragePct >= 70
      ? "text-green-400"
      : stats.coveragePct >= 40
        ? "text-yellow-400"
        : "text-red-400";

  const coveredWidth = stats.covered + stats.gaps > 0 ? (stats.covered / (stats.covered + stats.gaps)) * 100 : 0;
  const gapWidth = stats.covered + stats.gaps > 0 ? (stats.gaps / (stats.covered + stats.gaps)) * 100 : 0;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Purple Team Coverage Map</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          Atomic Red Team simulations paired with detection rules — gaps highlighted
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="stat-card">
          <div className={`stat-value ${coverageColor}`}>{stats.coveragePct}%</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Coverage Score</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{stats.withAtomics + stats.detectionOnly}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Techniques Assessed</div>
        </div>
        <div className="stat-card border-green-900/40">
          <div className="stat-value text-green-400">{stats.covered}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Fully Covered</div>
        </div>
        <div className="stat-card border-red-900/40">
          <div className="stat-value text-red-400">{stats.gaps}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Detection Gaps</div>
        </div>
        <div className="stat-card border-blue-900/40">
          <div className="stat-value text-blue-400">{stats.detectionOnly}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">Detection Only</div>
        </div>
      </div>

      <div className="card py-3 px-4">
        <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] mb-2">
          <span>Coverage ratio (atomics with detections)</span>
          <span>{stats.covered} covered / {stats.gaps} gaps</span>
        </div>
        <div className="flex h-3 rounded-full overflow-hidden bg-[var(--bg-tertiary)]">
          <div className="bg-green-500 transition-all" style={{ width: `${coveredWidth}%` }} />
          <div className="bg-red-500 transition-all" style={{ width: `${gapWidth}%` }} />
        </div>
        <div className="flex gap-4 mt-2 text-xs text-[var(--text-secondary)]">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />
            Covered
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
            Gap (attack but no detection)
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" />
            Detection only
          </span>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex gap-2 flex-wrap">
          {(
            [
              { label: "All", value: "" },
              { label: "Gaps Only", value: "gap" },
              { label: "Covered", value: "covered" },
              { label: "Detection Only", value: "detection-only" },
            ] as { label: string; value: string }[]
          ).map(({ label, value }) => {
            const isActive = (searchParams.status ?? "") === value;
            const accent = value === "gap" ? "bg-red-700 text-white" : "bg-[var(--accent)] text-white";
            return (
              <Link
                key={value}
                href={buildUrl({ status: value })}
                className={`px-3 py-1.5 rounded-lg text-sm ${
                  isActive ? accent : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                {label}
              </Link>
            );
          })}
        </div>

        <form action="/purple-team" className="flex gap-3 flex-wrap">
          <input type="hidden" name="status" value={searchParams.status ?? ""} />
          <input type="hidden" name="category" value={activeCategory} />
          <select name="tactic" defaultValue={activeTactic} className="text-sm">
            <option value="">All Tactics</option>
            {stats.byTactic.map((t) => (
              <option key={t.shortName} value={t.shortName}>
                {t.name}
              </option>
            ))}
          </select>
          <input
            type="search"
            name="search"
            placeholder="Search techniques..."
            defaultValue={searchParams.search ?? ""}
            className="flex-1 min-w-[200px]"
          />
          <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">
            Filter
          </button>
        </form>

        <div className="flex gap-2 flex-wrap">
          <Link
            href={buildUrl({ category: "" })}
            className={`px-2.5 py-1 rounded-lg text-xs ${
              !activeCategory ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
            }`}
          >
            All Categories
          </Link>
          {stats.byCategory.slice(0, 12).map((c) => (
            <Link
              key={c.slug}
              href={buildUrl({ category: activeCategory === c.slug ? "" : c.slug })}
              className={`px-2.5 py-1 rounded-lg text-xs ${
                activeCategory === c.slug ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
              }`}
            >
              {c.name}
            </Link>
          ))}
        </div>
      </div>

      <div className="space-y-1">
        <div className="grid grid-cols-12 gap-2 px-3 py-1 text-xs text-[var(--text-secondary)]">
          <div className="col-span-1">Status</div>
          <div className="col-span-4">Technique</div>
          <div className="col-span-3">Tactics</div>
          <div className="col-span-1 text-center">Atomics</div>
          <div className="col-span-1 text-center">Detections</div>
          <div className="col-span-2">Action</div>
        </div>

        {items.length === 0 && (
          <div className="card text-center text-[var(--text-secondary)] py-10">
            No techniques match the current filters.
          </div>
        )}

        {items.map((item) => (
          <Link
            key={item.id}
            href={`/purple-team/${item.id}`}
            className={`grid grid-cols-12 gap-2 items-center px-3 py-2.5 rounded-lg border text-sm hover:opacity-90 transition-opacity ${STATUS_ROW[item.status]}`}
          >
            <div className="col-span-1 flex items-center gap-1.5">
              <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${STATUS_DOT[item.status]}`} />
            </div>
            <div className="col-span-4 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-[var(--accent)] shrink-0">{item.externalId}</span>
                <span className="truncate font-medium">{item.name}</span>
              </div>
            </div>
            <div className="col-span-3 flex gap-1 flex-wrap">
              {item.tactics.slice(0, 2).map((tac) => (
                <span key={tac.id} className="badge bg-blue-900/30 text-blue-400 text-[10px]">
                  {tac.name}
                </span>
              ))}
              {item.tactics.length > 2 && (
                <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">+{item.tactics.length - 2}</span>
              )}
            </div>
            <div className="col-span-1 text-center">
              <span className={`badge text-xs ${item.atomicCount > 0 ? "bg-green-900/40 text-green-400" : "bg-zinc-800 text-zinc-500"}`}>
                {item.atomicCount}
              </span>
            </div>
            <div className="col-span-1 text-center">
              <span className={`badge text-xs ${item.detectionCount > 0 ? "bg-blue-900/40 text-blue-400" : "bg-zinc-800 text-zinc-500"}`}>
                {item.detectionCount}
              </span>
            </div>
            <div className="col-span-2">
              <span className={`badge text-[10px] ${STATUS_BADGE[item.status]}`}>{STATUS_LABEL[item.status]}</span>
              {item.status === "gap" && (
                <p className="text-[10px] text-red-400/80 mt-0.5 leading-tight">Write detection rule</p>
              )}
            </div>
          </Link>
        ))}
      </div>

      <div className="text-xs text-[var(--text-secondary)]">
        Showing {items.length} techniques
      </div>
    </div>
  );
}
