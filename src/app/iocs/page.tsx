import { prisma } from "@/lib/db";
import Link from "next/link";
import { IOCImport } from "@/components/import/IOCImport";
import { EnrichButton } from "./EnrichButton";

const TYPE_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  ipv4: { bg: "bg-red-900/50", text: "text-red-400", label: "IPv4" },
  ipv6: { bg: "bg-red-900/50", text: "text-red-400", label: "IPv6" },
  sha256: { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-256" },
  md5: { bg: "bg-purple-900/50", text: "text-purple-400", label: "MD5" },
  sha1: { bg: "bg-purple-900/50", text: "text-purple-400", label: "SHA-1" },
  domain: { bg: "bg-blue-900/50", text: "text-blue-400", label: "Domain" },
  url: { bg: "bg-cyan-900/50", text: "text-cyan-400", label: "URL" },
};

export default async function IOCsPage(props: {
  searchParams: Promise<{ page?: string; search?: string; type?: string }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const take = 50;
  const skip = (page - 1) * take;

  const where: Record<string, unknown> = {};
  if (searchParams.search) {
    where.OR = [
      { value: { contains: searchParams.search } },
      { description: { contains: searchParams.search } },
      { source: { contains: searchParams.search } },
    ];
  }
  if (searchParams.type) where.type = searchParams.type;

  const [iocs, total, typeCounts] = await Promise.all([
    prisma.iOC.findMany({
      where: where as never,
      include: { advisory: { select: { id: true, advisoryId: true, title: true } } },
      orderBy: { createdAt: "desc" },
      skip,
      take,
    }),
    prisma.iOC.count({ where: where as never }),
    prisma.iOC.groupBy({
      by: ["type"],
      _count: true,
      orderBy: { _count: { type: "desc" } },
    }),
  ]);

  const pages = Math.ceil(total / take);
  const activeType = searchParams.type ?? "";

  function buildUrl(overrides: Record<string, string>) {
    const params = new URLSearchParams();
    const merged = {
      search: searchParams.search ?? "",
      type: searchParams.type ?? "",
      page: "1",
      ...overrides,
    };
    for (const [k, v] of Object.entries(merged)) {
      if (v) params.set(k, v);
    }
    return `/iocs?${params.toString()}`;
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Indicators of Compromise</h1>
        <p className="text-sm text-[var(--text-secondary)]">
          {total.toLocaleString()} IOCs — malicious IPs, hashes, domains, URLs
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {typeCounts.map((tc) => {
          const style = TYPE_STYLES[tc.type] ?? { bg: "bg-zinc-800", text: "text-zinc-400", label: tc.type };
          return (
            <Link
              key={tc.type}
              href={buildUrl({ type: activeType === tc.type ? "" : tc.type })}
              className={`stat-card hover:border-[var(--accent)] transition-colors cursor-pointer ${
                activeType === tc.type ? "border-[var(--accent)]" : ""
              }`}
            >
              <div className={`stat-value text-lg ${style.text}`}>{tc._count}</div>
              <div className="text-xs text-[var(--text-secondary)]">{style.label}</div>
            </Link>
          );
        })}
      </div>

      <IOCImport />

      <form className="flex gap-3" action="/iocs">
        <input type="hidden" name="type" value={activeType} />
        <input
          type="search"
          name="search"
          placeholder="Search IPs, hashes, domains..."
          defaultValue={searchParams.search ?? ""}
          className="flex-1"
        />
        <button type="submit" className="px-4 py-2 bg-[var(--accent)] text-white rounded-lg text-sm">Filter</button>
      </form>

      <div className="space-y-2">
        {iocs.map((ioc) => {
          const style = TYPE_STYLES[ioc.type] ?? { bg: "bg-zinc-800", text: "text-zinc-400", label: ioc.type };
          return (
            <div key={ioc.id} className="card flex items-start gap-4 !py-3">
              <span className={`badge ${style.bg} ${style.text} shrink-0 mt-0.5`}>{style.label}</span>
              <div className="flex-1 min-w-0">
                <code className="text-sm text-[var(--accent)] break-all font-mono">{ioc.value}</code>
                {ioc.description && (
                  <p className="text-xs text-[var(--text-secondary)] mt-1">{ioc.description}</p>
                )}
                <div className="flex items-center gap-3 mt-1.5">
                  <span className="text-[10px] text-[var(--text-secondary)]">{ioc.source}</span>
                  {ioc.advisory && (
                    <Link href={`/advisories/${ioc.advisory.id}`} className="text-[10px] text-[var(--accent)] hover:underline">
                      {ioc.advisory.advisoryId}
                    </Link>
                  )}
                  {ioc.firstSeen && (
                    <span className="text-[10px] text-[var(--text-secondary)]">
                      First seen: {new Date(ioc.firstSeen).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              <EnrichButton indicator={ioc.value} iocId={ioc.id} />
            </div>
          );
        })}
      </div>

      {total === 0 && (
        <div className="card text-center py-12">
          <p className="text-[var(--text-secondary)]">No IOCs match your search.</p>
        </div>
      )}

      {pages > 1 && (
        <div className="flex justify-center gap-2">
          {page > 1 && (
            <Link href={buildUrl({ page: String(page - 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Prev</Link>
          )}
          <span className="px-3 py-1 text-sm text-[var(--text-secondary)]">Page {page} of {pages}</span>
          {page < pages && (
            <Link href={buildUrl({ page: String(page + 1) })} className="px-3 py-1 rounded bg-[var(--bg-tertiary)] text-sm">Next</Link>
          )}
        </div>
      )}
    </div>
  );
}
