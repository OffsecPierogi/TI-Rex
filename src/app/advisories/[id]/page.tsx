import { getAdvisoryDetail } from "@/actions/advisories";
import { notFound } from "next/navigation";
import Link from "next/link";

export default async function AdvisoryDetailPage(props: { params: Promise<{ id: string }> }) {
  const { id } = await props.params;
  const advisory = await getAdvisoryDetail(id);
  if (!advisory) notFound();

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <span className="text-sm font-mono text-[var(--accent)]">{advisory.cveId ?? advisory.advisoryId}</span>
        <h1 className="text-2xl font-bold mt-1">{advisory.title}</h1>
        <div className="flex gap-2 mt-2">
          <span className="badge bg-zinc-800 text-zinc-400">{advisory.type}</span>
          {advisory.severity && <span className="badge bg-red-900/50 text-red-400">{advisory.severity}</span>}
          {advisory.knownRansomware && <span className="badge bg-red-900/50 text-red-400">Known Ransomware Use</span>}
        </div>
      </div>

      <div className="card">
        <h2 className="text-lg font-semibold mb-2">Description</h2>
        <p className="text-sm text-[var(--text-secondary)]">{advisory.description}</p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card">
          <div className="text-xs text-[var(--text-secondary)]">Vendor / Product</div>
          <div className="text-sm mt-1">{advisory.vendorProject} — {advisory.product}</div>
        </div>
        <div className="card">
          <div className="text-xs text-[var(--text-secondary)]">Dates</div>
          <div className="text-sm mt-1">
            Added: {advisory.dateAdded && new Date(advisory.dateAdded).toLocaleDateString()}
            {advisory.dueDate && ` · Due: ${new Date(advisory.dueDate).toLocaleDateString()}`}
          </div>
        </div>
      </div>

      {advisory.iocs.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-3">Indicators of Compromise ({advisory.iocs.length})</h2>
          <div className="space-y-2">
            {advisory.iocs.map((ioc) => (
              <div key={ioc.id} className="p-2 border border-[var(--border)] rounded flex items-center gap-3">
                <span className="badge bg-zinc-800 text-zinc-400">{ioc.type}</span>
                <code className="text-sm text-[var(--accent)] break-all">{ioc.value}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {advisory.url && (
        <a href={advisory.url} target="_blank" rel="noopener noreferrer" className="text-sm text-[var(--accent)] hover:underline">
          View on NVD →
        </a>
      )}

      <Link href="/advisories" className="text-sm text-[var(--text-secondary)] hover:underline block">
        ← Back to advisories
      </Link>
    </div>
  );
}
