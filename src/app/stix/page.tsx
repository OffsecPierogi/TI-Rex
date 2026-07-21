import Link from "next/link";
import { getStixExportOptions, getExportableActors } from "@/actions/stix";

const TYPE_CARDS = [
  {
    type: "actors",
    label: "Threat Actors",
    description: "Export threat actors as STIX intrusion-set objects with associated relationships.",
    color: "text-red-400",
  },
  {
    type: "malware",
    label: "Malware",
    description: "Export malware families as STIX malware objects with type classifications.",
    color: "text-orange-400",
  },
  {
    type: "techniques",
    label: "Techniques",
    description: "Export ATT&CK techniques as STIX attack-pattern objects with kill chain phases.",
    color: "text-blue-400",
  },
  {
    type: "iocs",
    label: "Indicators of Compromise",
    description: "Export IOCs as STIX indicator objects with STIX patterns.",
    color: "text-green-400",
  },
  {
    type: "full",
    label: "Full Export",
    description: "Export all entity types into a single STIX bundle with relationships.",
    color: "text-purple-400",
  },
];

export default async function StixPage(
  props: { searchParams: Promise<{ q?: string }> }
) {
  const { q = "" } = await props.searchParams;

  const [options, actors] = await Promise.all([
    getStixExportOptions(),
    getExportableActors(),
  ]);

  const filteredActors = q
    ? actors.filter(
        (a) =>
          a.name.toLowerCase().includes(q.toLowerCase()) ||
          a.externalId.toLowerCase().includes(q.toLowerCase())
      )
    : actors;

  const countMap: Record<string, number> = {
    actors: options.actors,
    malware: options.malware,
    techniques: options.techniques,
    iocs: options.iocs,
    full:
      options.actors + options.malware + options.techniques + options.iocs,
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">STIX/TAXII Export</h1>
        <p className="text-sm text-[var(--text-secondary)] mt-1">
          Export threat intelligence data in STIX 2.1 format for sharing via TAXII servers or importing into other platforms.
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Threat Actors", value: options.actors },
          { label: "Malware", value: options.malware },
          { label: "Techniques", value: options.techniques },
          { label: "IOCs", value: options.iocs },
        ].map((s) => (
          <div key={s.label} className="stat-card">
            <div className="stat-value">{s.value.toLocaleString()}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {TYPE_CARDS.map((card) => (
          <Link
            key={card.type}
            href={`/stix/${card.type}`}
            className="card hover:border-[var(--accent)] transition-colors group"
          >
            <div className="flex items-center justify-between mb-2">
              <h3 className={`font-semibold ${card.color}`}>{card.label}</h3>
              <span className="text-lg font-bold text-[var(--text-secondary)] group-hover:text-[var(--accent)] transition-colors">
                {countMap[card.type]?.toLocaleString()}
              </span>
            </div>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed mb-3">
              {card.description}
            </p>
            <span className="text-xs font-medium text-[var(--accent)]">
              Export STIX Bundle →
            </span>
          </Link>
        ))}
      </div>

      <div className="card space-y-4">
        <div>
          <h2 className="text-base font-semibold mb-1">Single Actor Export</h2>
          <p className="text-xs text-[var(--text-secondary)]">
            Generate a STIX bundle for a specific actor including their techniques, malware, and relationships.
          </p>
        </div>

        <form method="GET" action="/stix">
          <input
            type="search"
            name="q"
            defaultValue={q}
            placeholder="Filter actors by name or ID..."
            className="w-full max-w-md"
          />
        </form>

        <div className="max-h-72 overflow-y-auto border border-[var(--border)] rounded-lg divide-y divide-[var(--border)]">
          {filteredActors.length === 0 && (
            <p className="p-4 text-sm text-[var(--text-secondary)]">No actors found.</p>
          )}
          {filteredActors.slice(0, 100).map((a) => (
            <div
              key={a.id}
              className="flex items-center justify-between px-4 py-2 hover:bg-[var(--bg-tertiary)]"
            >
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs text-[var(--accent)] w-24 shrink-0">
                  {a.externalId}
                </span>
                <span className="text-sm">{a.name}</span>
                {a.country && (
                  <span className="badge bg-zinc-800 text-zinc-400 text-[10px]">
                    {a.country}
                  </span>
                )}
                <span className="text-xs text-[var(--text-secondary)]">
                  {a._count.procedures} proc
                </span>
              </div>
              <Link
                href={`/stix/actor/${a.id}`}
                className="px-3 py-1 text-xs bg-[var(--accent)] text-white rounded-lg hover:opacity-90 transition-opacity shrink-0"
              >
                Export STIX
              </Link>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
