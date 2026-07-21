import { getMatrixData } from "@/actions/matrix";
import Link from "next/link";

export default async function MatrixPage(props: {
  searchParams: Promise<{ matrix?: string }>;
}) {
  const searchParams = await props.searchParams;
  const matrixName = searchParams.matrix || "enterprise-attack";
  const tactics = await getMatrixData(matrixName);

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">MITRE ATT&CK Matrix</h1>
          <p className="text-sm text-[var(--text-secondary)]">
            {tactics.reduce((sum, t) => sum + t.techniques.length, 0)} techniques across {tactics.length} tactics
          </p>
        </div>
        <div className="flex gap-2">
          {["enterprise-attack", "mobile-attack", "ics-attack"].map((m) => (
            <Link
              key={m}
              href={`/matrix?matrix=${m}`}
              className={`px-3 py-1.5 rounded-lg text-sm ${
                matrixName === m ? "bg-[var(--accent)] text-white" : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]"
              }`}
            >
              {m.replace("-attack", "").toUpperCase()}
            </Link>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto pb-4">
        <div className="flex gap-2 min-w-max">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="w-48 shrink-0">
              <div className="sticky top-0 bg-[var(--bg-tertiary)] p-2 rounded-t-lg border border-[var(--border)] text-center">
                <div className="text-xs font-semibold">{tactic.name}</div>
                <div className="text-[10px] text-[var(--text-secondary)]">{tactic.techniques.length} techniques</div>
              </div>
              <div className="border-x border-b border-[var(--border)] rounded-b-lg max-h-[70vh] overflow-y-auto">
                {tactic.techniques.map((tech) => (
                  <Link
                    key={tech.id}
                    href={`/techniques/${tech.id}`}
                    className="block p-2 border-b border-[var(--border)] hover:bg-[var(--bg-tertiary)] transition-colors"
                  >
                    <div className="text-[11px] font-mono text-[var(--accent)]">{tech.externalId}</div>
                    <div className="text-xs truncate">{tech.name}</div>
                    <div className="flex gap-1 mt-0.5">
                      {tech.subCount > 0 && (
                        <span className="text-[9px] text-[var(--text-secondary)]">{tech.subCount} subs</span>
                      )}
                      {tech.procedureCount > 0 && (
                        <span className="text-[9px] text-[var(--text-secondary)]">{tech.procedureCount} proc</span>
                      )}
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
