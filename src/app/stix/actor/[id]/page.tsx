import { notFound } from "next/navigation";
import Link from "next/link";
import { exportActorStix } from "@/actions/stix";
import { StixActions } from "../../[type]/StixActions";

function bundleStats(bundle: { objects: Record<string, unknown>[] }) {
  const counts: Record<string, number> = {};
  for (const obj of bundle.objects) {
    const t = obj.type as string;
    counts[t] = (counts[t] || 0) + 1;
  }
  return counts;
}

export default async function StixActorPage(
  props: { params: Promise<{ id: string }> }
) {
  const { id } = await props.params;
  const bundle = await exportActorStix(id);
  if (!bundle) notFound();

  const actorObj = bundle.objects.find((o) => o.type === "intrusion-set") as
    | { name: string; id: string }
    | undefined;
  const actorName = actorObj?.name ?? "Unknown Actor";

  const jsonString = JSON.stringify(bundle, null, 2);
  const stats = bundleStats(bundle);
  const slug = actorName.replace(/[^a-z0-9]+/gi, "-").toLowerCase();
  const filename = `stix-${slug}-${new Date().toISOString().slice(0, 10)}.json`;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Link
            href="/stix"
            className="text-sm text-[var(--text-secondary)] hover:underline"
          >
            ← STIX Export
          </Link>
          <h1 className="text-2xl font-bold mt-1">
            {actorName} — STIX 2.1 Bundle
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Single actor export with associated techniques, malware, and relationships
          </p>
        </div>
        <StixActions jsonData={jsonString} filename={filename} />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {Object.entries(stats).map(([objType, count]) => (
          <div key={objType} className="stat-card">
            <div className="stat-value">{count}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1 truncate">
              {objType}
            </div>
          </div>
        ))}
        <div className="stat-card">
          <div className="stat-value">{bundle.objects.length}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">
            Total Objects
          </div>
        </div>
      </div>

      <div className="card">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--text-secondary)]">
            STIX Bundle Preview
          </h2>
          <span className="text-xs text-[var(--text-secondary)]">
            {(jsonString.length / 1024).toFixed(1)} KB
          </span>
        </div>
        <pre className="code-block text-xs overflow-auto max-h-[70vh]">
          {jsonString}
        </pre>
      </div>
    </div>
  );
}
