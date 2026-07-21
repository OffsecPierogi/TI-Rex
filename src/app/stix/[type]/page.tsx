import { notFound } from "next/navigation";
import Link from "next/link";
import { exportBulkStix, exportFullStix } from "@/actions/stix";
import { StixActions } from "./StixActions";

const TYPE_META: Record<string, { label: string; description: string }> = {
  actors: { label: "Threat Actors", description: "STIX intrusion-set objects" },
  malware: { label: "Malware", description: "STIX malware objects" },
  techniques: { label: "Techniques", description: "STIX attack-pattern objects" },
  iocs: { label: "IOCs", description: "STIX indicator objects" },
  full: { label: "Full Export", description: "All entity types in one bundle" },
};

function bundleStats(bundle: { objects: Record<string, unknown>[] }) {
  const counts: Record<string, number> = {};
  for (const obj of bundle.objects) {
    const t = obj.type as string;
    counts[t] = (counts[t] || 0) + 1;
  }
  return counts;
}

export default async function StixTypePage(
  props: { params: Promise<{ type: string }> }
) {
  const { type } = await props.params;

  const validTypes = ["actors", "malware", "techniques", "iocs", "full"];
  if (!validTypes.includes(type)) notFound();

  const meta = TYPE_META[type];
  const bundle =
    type === "full"
      ? await exportFullStix()
      : await exportBulkStix(type as "actors" | "malware" | "techniques" | "iocs");

  const jsonString = JSON.stringify(bundle, null, 2);
  const stats = bundleStats(bundle);
  const filename = `stix-${type}-${new Date().toISOString().slice(0, 10)}.json`;

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
            {meta.label} — STIX 2.1 Bundle
          </h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            {meta.description}
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
