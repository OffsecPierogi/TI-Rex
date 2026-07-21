"use client";

import { useState, useTransition, useCallback } from "react";
import {
  getActorLayer,
  getMalwareLayer,
  getCategoryLayer,
  getComparisonLayer,
  type LayerHighlight,
} from "@/actions/matrix";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "🇷🇺", "China": "🇨🇳", "North Korea": "🇰🇵", "Iran": "🇮🇷",
  "Vietnam": "🇻🇳", "India": "🇮🇳", "Pakistan": "🇵🇰", "Turkey": "🇹🇷",
  "Lebanon": "🇱🇧", "South Korea": "🇰🇷", "USA": "🇺🇸",
  "Israel": "🇮🇱", "Belarus": "🇧🇾", "Brazil": "🇧🇷",
  "United Kingdom": "🇬🇧", "Nigeria": "🇳🇬", "Venezuela": "🇻🇪", "Mexico": "🇲🇽",
  "Palestine": "🇵🇸", "Colombia": "🇨🇴",
};

interface TacticData {
  id: string;
  name: string;
  shortName: string;
  externalId: string;
  techniques: {
    id: string;
    externalId: string;
    name: string;
    subCount: number;
    procedureCount: number;
  }[];
}

interface Actor { id: string; name: string; externalId: string; country: string | null; techniqueCount: number }
interface MalwareItem { id: string; name: string; externalId: string; type: string | null; techniqueCount: number }
interface CategoryItem { slug: string; name: string; color: string | null; techniqueCount: number }

interface ActiveLayer {
  name: string;
  color: string;
  highlights: Map<string, LayerHighlight>;
  maxScore: number;
}

type PanelTab = "actors" | "malware" | "categories" | "compare";

function colorWithOpacity(hex: string, opacity: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${opacity})`;
}

export function InteractiveNavigator({
  matrixData,
  actors,
  malware,
  categories,
}: {
  matrixData: TacticData[];
  actors: Actor[];
  malware: MalwareItem[];
  categories: CategoryItem[];
}) {
  const [layer, setLayer] = useState<ActiveLayer | null>(null);
  const [hoveredTech, setHoveredTech] = useState<string | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("actors");
  const [search, setSearch] = useState("");
  const [selectedForCompare, setSelectedForCompare] = useState<Set<string>>(new Set());
  const [panelOpen, setPanelOpen] = useState(true);
  const [isPending, startTransition] = useTransition();

  const loadActorLayer = useCallback((actorId: string) => {
    startTransition(async () => {
      const data = await getActorLayer(actorId);
      const highlights = new Map(data.highlights.map((h) => [h.techniqueId, h]));
      const maxScore = Math.max(...data.highlights.map((h) => h.score), 1);
      setLayer({ name: data.name, color: data.color, highlights, maxScore });
    });
  }, []);

  const loadMalwareLayer = useCallback((malwareId: string) => {
    startTransition(async () => {
      const data = await getMalwareLayer(malwareId);
      const highlights = new Map(data.highlights.map((h) => [h.techniqueId, h]));
      const maxScore = Math.max(...data.highlights.map((h) => h.score), 1);
      setLayer({ name: data.name, color: data.color, highlights, maxScore });
    });
  }, []);

  const loadCategoryLayer = useCallback((slug: string) => {
    startTransition(async () => {
      const data = await getCategoryLayer(slug);
      const highlights = new Map(data.highlights.map((h) => [h.techniqueId, h]));
      const maxScore = Math.max(...data.highlights.map((h) => h.score), 1);
      setLayer({ name: data.name, color: data.color, highlights, maxScore });
    });
  }, []);

  const loadComparisonLayer = useCallback(() => {
    const ids = [...selectedForCompare];
    if (ids.length < 2) return;
    startTransition(async () => {
      const data = await getComparisonLayer(ids);
      const highlights = new Map(data.highlights.map((h) => [h.techniqueId, h]));
      const maxScore = Math.max(...data.highlights.map((h) => h.score), 1);
      setLayer({ name: data.name, color: data.color, highlights, maxScore });
    });
  }, [selectedForCompare]);

  const toggleCompare = (id: string) => {
    setSelectedForCompare((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const clearLayer = () => { setLayer(null); };
  const filtered = search.toLowerCase();

  const totalTechniques = matrixData.reduce((s, t) => s + t.techniques.length, 0);
  const highlightedCount = layer ? layer.highlights.size : 0;
  const coveragePct = layer ? Math.round((highlightedCount / totalTechniques) * 100) : 0;

  const hoveredHighlight = hoveredTech && layer ? layer.highlights.get(hoveredTech) : null;

  const exportUrl = layer
    ? (() => {
        if (panelTab === "compare" && selectedForCompare.size >= 2) {
          return `/api/navigator?type=comparison&ids=${[...selectedForCompare].join(",")}`;
        }
        return null;
      })()
    : null;

  return (
    <div className="flex h-[calc(100vh-5rem)] gap-0">
      {/* Side panel */}
      {panelOpen && (
        <div className="w-72 shrink-0 border-r border-[var(--border)] flex flex-col bg-[var(--bg-secondary)] overflow-hidden">
          <div className="p-3 border-b border-[var(--border)]">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-sm font-semibold">Layer Source</h2>
              <button onClick={() => setPanelOpen(false)} className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)]">Hide</button>
            </div>
            <div className="flex gap-1">
              {(["actors", "malware", "categories", "compare"] as PanelTab[]).map((t) => (
                <button
                  key={t}
                  onClick={() => { setPanelTab(t); setSearch(""); }}
                  className={`px-2 py-1 rounded text-[10px] transition-colors ${
                    panelTab === t ? "bg-[var(--accent)] text-white" : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {t === "compare" ? "Compare" : t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              ))}
            </div>
          </div>

          <div className="p-2">
            <input
              type="search"
              placeholder={`Search ${panelTab}...`}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full text-xs py-1.5"
            />
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
            {panelTab === "actors" && actors
              .filter((a) => !filtered || a.name.toLowerCase().includes(filtered) || a.country?.toLowerCase().includes(filtered))
              .map((a) => (
                <button
                  key={a.id}
                  onClick={() => loadActorLayer(a.id)}
                  className={`w-full text-left p-2 rounded text-xs hover:bg-[var(--bg-tertiary)] transition-colors flex items-center gap-2 ${
                    layer?.name === a.name ? "bg-[var(--bg-tertiary)] border border-[var(--accent)]" : ""
                  }`}
                >
                  {a.country && <span className="text-sm shrink-0">{COUNTRY_FLAGS[a.country] ?? ""}</span>}
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{a.name}</div>
                    <div className="text-[10px] text-[var(--text-secondary)]">{a.externalId} · {a.techniqueCount} proc</div>
                  </div>
                </button>
              ))}

            {panelTab === "malware" && malware
              .filter((m) => !filtered || m.name.toLowerCase().includes(filtered) || m.type?.toLowerCase().includes(filtered))
              .map((m) => (
                <button
                  key={m.id}
                  onClick={() => loadMalwareLayer(m.id)}
                  className={`w-full text-left p-2 rounded text-xs hover:bg-[var(--bg-tertiary)] transition-colors ${
                    layer?.name === m.name ? "bg-[var(--bg-tertiary)] border border-[var(--accent)]" : ""
                  }`}
                >
                  <div className="truncate font-medium">{m.name}</div>
                  <div className="text-[10px] text-[var(--text-secondary)]">{m.externalId} · {m.type} · {m.techniqueCount} proc</div>
                </button>
              ))}

            {panelTab === "categories" && categories
              .filter((c) => !filtered || c.name.toLowerCase().includes(filtered))
              .map((c) => (
                <button
                  key={c.slug}
                  onClick={() => loadCategoryLayer(c.slug)}
                  className={`w-full text-left p-2 rounded text-xs hover:bg-[var(--bg-tertiary)] transition-colors flex items-center gap-2 ${
                    layer?.name === c.name ? "bg-[var(--bg-tertiary)] border border-[var(--accent)]" : ""
                  }`}
                >
                  <span className="w-3 h-3 rounded-full shrink-0" style={{ background: c.color ?? "#666" }} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{c.name}</div>
                    <div className="text-[10px] text-[var(--text-secondary)]">{c.techniqueCount} techniques</div>
                  </div>
                </button>
              ))}

            {panelTab === "compare" && (
              <>
                {selectedForCompare.size >= 2 && (
                  <button
                    onClick={loadComparisonLayer}
                    className="w-full p-2 rounded text-xs bg-[var(--accent)] text-white mb-2 hover:opacity-90"
                  >
                    Visualize Comparison ({selectedForCompare.size} actors)
                  </button>
                )}
                {actors
                  .filter((a) => !filtered || a.name.toLowerCase().includes(filtered) || a.country?.toLowerCase().includes(filtered))
                  .map((a) => (
                    <button
                      key={a.id}
                      onClick={() => toggleCompare(a.id)}
                      className={`w-full text-left p-2 rounded text-xs hover:bg-[var(--bg-tertiary)] transition-colors flex items-center gap-2 ${
                        selectedForCompare.has(a.id) ? "bg-[var(--accent)]/10 border border-[var(--accent)]" : ""
                      }`}
                    >
                      <span className={`w-3.5 h-3.5 rounded border-2 flex items-center justify-center text-[8px] shrink-0 ${
                        selectedForCompare.has(a.id) ? "border-[var(--accent)] bg-[var(--accent)] text-white" : "border-[var(--border)]"
                      }`}>
                        {selectedForCompare.has(a.id) ? "✓" : ""}
                      </span>
                      {a.country && <span className="text-sm shrink-0">{COUNTRY_FLAGS[a.country] ?? ""}</span>}
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-medium">{a.name}</div>
                        <div className="text-[10px] text-[var(--text-secondary)]">{a.externalId}</div>
                      </div>
                    </button>
                  ))}
              </>
            )}
          </div>
        </div>
      )}

      {/* Main matrix area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <div className="flex items-center justify-between p-3 border-b border-[var(--border)] shrink-0 bg-[var(--bg-primary)]">
          <div className="flex items-center gap-3">
            {!panelOpen && (
              <button onClick={() => setPanelOpen(true)} className="text-xs text-[var(--accent)] hover:underline">
                Show Panel
              </button>
            )}
            <h1 className="text-lg font-bold">ATT&CK Navigator</h1>
            {isPending && <span className="text-xs text-[var(--text-secondary)] animate-pulse">Loading layer...</span>}
          </div>

          <div className="flex items-center gap-3">
            {layer && (
              <>
                <div className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded" style={{ background: layer.color }} />
                  <span className="text-sm font-medium">{layer.name}</span>
                  <span className="text-xs text-[var(--text-secondary)]">
                    {highlightedCount}/{totalTechniques} techniques ({coveragePct}%)
                  </span>
                </div>
                <a
                  href={exportUrl ?? `/api/navigator?type=${panelTab === "malware" ? "malware" : panelTab === "categories" ? "category" : "actor"}&id=placeholder`}
                  download
                  className="text-xs text-[var(--accent)] hover:underline"
                  onClick={(e) => {
                    if (!exportUrl && panelTab !== "compare") return;
                    if (!exportUrl) e.preventDefault();
                  }}
                  style={{ display: exportUrl ? "inline" : "none" }}
                >
                  Export JSON
                </a>
                <button onClick={clearLayer} className="text-xs text-[var(--text-secondary)] hover:text-red-400">
                  Clear
                </button>
              </>
            )}
            {!layer && (
              <span className="text-xs text-[var(--text-secondary)]">
                Select an actor, malware, or category to overlay on the matrix
              </span>
            )}
          </div>
        </div>

        {/* Tooltip */}
        {hoveredHighlight && hoveredTech && (
          <div className="absolute top-16 right-8 z-50 p-3 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] shadow-lg max-w-xs">
            <div className="text-xs font-mono text-[var(--accent)]">{hoveredTech}</div>
            <div className="text-xs text-[var(--text-secondary)] mt-1">{hoveredHighlight.comment}</div>
            <div className="text-xs mt-1">Score: <span className="font-bold">{hoveredHighlight.score}</span></div>
          </div>
        )}

        {/* Matrix grid */}
        <div className="flex-1 overflow-auto p-3">
          <div className="flex gap-1 min-w-max">
            {matrixData.map((tactic) => (
              <div key={tactic.id} className="w-36 shrink-0">
                <div className="sticky top-0 z-10 bg-[var(--bg-tertiary)] p-1.5 rounded-t border border-[var(--border)] text-center">
                  <div className="text-[10px] font-semibold leading-tight">{tactic.name}</div>
                  <div className="text-[9px] text-[var(--text-secondary)]">
                    {tactic.techniques.length}
                    {layer && (() => {
                      const hit = tactic.techniques.filter((t) => layer.highlights.has(t.externalId)).length;
                      return hit > 0 ? ` (${hit} hit)` : "";
                    })()}
                  </div>
                </div>
                <div className="border-x border-b border-[var(--border)] rounded-b">
                  {tactic.techniques.map((tech) => {
                    const highlight = layer?.highlights.get(tech.externalId);
                    const isHighlighted = !!highlight;
                    const intensity = highlight ? Math.min(highlight.score / layer!.maxScore, 1) : 0;
                    const opacity = isHighlighted ? 0.2 + intensity * 0.6 : 0;

                    return (
                      <a
                        key={tech.id}
                        href={`/techniques/${tech.id}`}
                        className="block p-1.5 border-b border-[var(--border)] transition-all duration-150 relative group"
                        style={{
                          background: isHighlighted ? colorWithOpacity(layer!.color, opacity) : undefined,
                        }}
                        onMouseEnter={() => setHoveredTech(tech.externalId)}
                        onMouseLeave={() => setHoveredTech(null)}
                      >
                        <div className="flex items-center gap-1">
                          <span className={`text-[9px] font-mono ${isHighlighted ? "text-white font-bold" : "text-[var(--accent)]"}`}>
                            {tech.externalId}
                          </span>
                          {isHighlighted && (
                            <span className="text-[8px] font-bold text-white/80 ml-auto">
                              {highlight!.score}
                            </span>
                          )}
                        </div>
                        <div className={`text-[10px] leading-tight truncate ${isHighlighted ? "text-white/90" : "text-[var(--text-primary)]"}`}>
                          {tech.name}
                        </div>
                        {!isHighlighted && tech.subCount > 0 && (
                          <div className="text-[8px] text-[var(--text-secondary)]">{tech.subCount} sub</div>
                        )}
                      </a>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Legend bar */}
        {layer && (
          <div className="shrink-0 p-2 border-t border-[var(--border)] flex items-center gap-4 bg-[var(--bg-secondary)]">
            <span className="text-[10px] text-[var(--text-secondary)]">Score intensity:</span>
            <div className="flex items-center gap-1">
              <span className="w-6 h-4 rounded" style={{ background: colorWithOpacity(layer.color, 0.2) }} />
              <span className="text-[9px] text-[var(--text-secondary)]">Low</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-6 h-4 rounded" style={{ background: colorWithOpacity(layer.color, 0.5) }} />
              <span className="text-[9px] text-[var(--text-secondary)]">Med</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-6 h-4 rounded" style={{ background: colorWithOpacity(layer.color, 0.8) }} />
              <span className="text-[9px] text-[var(--text-secondary)]">High</span>
            </div>
            <span className="text-[10px] text-[var(--text-secondary)] ml-4">
              Click any technique to view details
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
