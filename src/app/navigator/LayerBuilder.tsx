"use client";

import { useState } from "react";

const COUNTRY_FLAGS: Record<string, string> = {
  "Russia": "🇷🇺", "China": "🇨🇳", "North Korea": "🇰🇵", "Iran": "🇮🇷",
  "Vietnam": "🇻🇳", "India": "🇮🇳", "Pakistan": "🇵🇰", "Turkey": "🇹🇷",
  "Lebanon": "🇱🇧", "South Korea": "🇰🇷", "USA": "🇺🇸",
  "Israel": "🇮🇱", "Belarus": "🇧🇾", "Brazil": "🇧🇷",
  "United Kingdom": "🇬🇧", "Nigeria": "🇳🇬", "Venezuela": "🇻🇪", "Mexico": "🇲🇽",
  "Palestine": "🇵🇸", "Colombia": "🇨🇴",
};

interface Actor {
  id: string;
  name: string;
  externalId: string;
  country: string | null;
  techniqueCount: number;
}

interface MalwareItem {
  id: string;
  name: string;
  externalId: string;
  type: string | null;
  techniqueCount: number;
}

interface CategoryItem {
  slug: string;
  name: string;
  color: string | null;
  techniqueCount: number;
}

type Tab = "actors" | "malware" | "categories" | "comparison";

export function NavigatorLayerBuilder({
  actors,
  malware,
  categories,
}: {
  actors: Actor[];
  malware: MalwareItem[];
  categories: CategoryItem[];
}) {
  const [tab, setTab] = useState<Tab>("actors");
  const [search, setSearch] = useState("");
  const [selectedActors, setSelectedActors] = useState<Set<string>>(new Set());

  const tabs: { key: Tab; label: string }[] = [
    { key: "actors", label: "Threat Actors" },
    { key: "malware", label: "Malware" },
    { key: "categories", label: "Categories" },
    { key: "comparison", label: "Compare Actors" },
  ];

  const filtered = search.toLowerCase();

  function toggleActor(id: string) {
    setSelectedActors((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="space-y-6">
      {/* Tab bar */}
      <div className="flex gap-2 border-b border-[var(--border)] pb-2">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => { setTab(t.key); setSearch(""); }}
            className={`px-4 py-2 rounded-t-lg text-sm transition-colors ${
              tab === t.key
                ? "bg-[var(--accent)] text-white"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Search */}
      {tab !== "comparison" && (
        <input
          type="search"
          placeholder={`Search ${tab}...`}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full"
        />
      )}

      {/* Actor list */}
      {tab === "actors" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {actors
            .filter((a) => !filtered || a.name.toLowerCase().includes(filtered) || (a.country?.toLowerCase().includes(filtered)))
            .map((a) => (
              <a
                key={a.id}
                href={`/api/navigator?type=actor&id=${a.id}`}
                download
                className="flex items-center justify-between p-3 rounded-lg border border-[var(--border)] hover:border-[var(--accent)] transition-colors"
              >
                <div className="flex items-center gap-2 min-w-0">
                  {a.country && <span>{COUNTRY_FLAGS[a.country] ?? ""}</span>}
                  <div className="min-w-0">
                    <div className="text-sm font-medium truncate">{a.name}</div>
                    <div className="text-[10px] text-[var(--text-secondary)] font-mono">{a.externalId}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs text-[var(--text-secondary)]">{a.techniqueCount} proc</span>
                  <DownloadIcon />
                </div>
              </a>
            ))}
        </div>
      )}

      {/* Malware list */}
      {tab === "malware" && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {malware
            .filter((m) => !filtered || m.name.toLowerCase().includes(filtered) || (m.type?.toLowerCase().includes(filtered)))
            .map((m) => (
              <a
                key={m.id}
                href={`/api/navigator?type=malware&id=${m.id}`}
                download
                className="flex items-center justify-between p-3 rounded-lg border border-[var(--border)] hover:border-[var(--accent)] transition-colors"
              >
                <div className="min-w-0">
                  <div className="text-sm font-medium truncate">{m.name}</div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[var(--text-secondary)] font-mono">{m.externalId}</span>
                    {m.type && <span className="text-[10px] text-[var(--text-secondary)]">{m.type}</span>}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs text-[var(--text-secondary)]">{m.techniqueCount} proc</span>
                  <DownloadIcon />
                </div>
              </a>
            ))}
        </div>
      )}

      {/* Categories */}
      {tab === "categories" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {categories.map((c) => (
            <a
              key={c.slug}
              href={`/api/navigator?type=category&id=${c.slug}`}
              download
              className="flex items-center justify-between p-4 rounded-lg border border-[var(--border)] hover:border-[var(--accent)] transition-colors"
            >
              <div className="flex items-center gap-3">
                <span className="w-4 h-4 rounded-full" style={{ background: c.color ?? "#666" }} />
                <div>
                  <div className="text-sm font-medium">{c.name}</div>
                  <div className="text-xs text-[var(--text-secondary)]">{c.techniqueCount} techniques</div>
                </div>
              </div>
              <DownloadIcon />
            </a>
          ))}
        </div>
      )}

      {/* Comparison builder */}
      {tab === "comparison" && (
        <div className="space-y-4">
          <p className="text-sm text-[var(--text-secondary)]">
            Select 2 or more threat actors to generate a comparison layer showing technique overlap.
            Techniques used by more actors score higher.
          </p>

          <input
            type="search"
            placeholder="Search actors..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full"
          />

          {selectedActors.size > 0 && (
            <div className="flex items-center gap-3 flex-wrap p-3 rounded-lg bg-[var(--bg-secondary)] border border-[var(--border)]">
              <span className="text-xs text-[var(--text-secondary)]">Selected:</span>
              {actors.filter((a) => selectedActors.has(a.id)).map((a) => (
                <button
                  key={a.id}
                  onClick={() => toggleActor(a.id)}
                  className="badge bg-[var(--accent)] text-white text-xs hover:opacity-80"
                >
                  {a.country && COUNTRY_FLAGS[a.country] ? `${COUNTRY_FLAGS[a.country]} ` : ""}{a.name} ✕
                </button>
              ))}
              {selectedActors.size >= 2 && (
                <a
                  href={`/api/navigator?type=comparison&ids=${[...selectedActors].join(",")}`}
                  download
                  className="ml-auto inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-[var(--accent)] text-white hover:opacity-90 transition-opacity"
                >
                  <DownloadIcon />
                  Export Comparison Layer ({selectedActors.size} actors)
                </a>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {actors
              .filter((a) => !filtered || a.name.toLowerCase().includes(filtered) || (a.country?.toLowerCase().includes(filtered)))
              .map((a) => (
                <button
                  key={a.id}
                  onClick={() => toggleActor(a.id)}
                  className={`flex items-center justify-between p-3 rounded-lg border transition-colors text-left ${
                    selectedActors.has(a.id)
                      ? "border-[var(--accent)] bg-[var(--accent)]/10"
                      : "border-[var(--border)] hover:border-[var(--accent)]"
                  }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={`w-4 h-4 rounded border-2 flex items-center justify-center text-[10px] ${
                      selectedActors.has(a.id)
                        ? "border-[var(--accent)] bg-[var(--accent)] text-white"
                        : "border-[var(--border)]"
                    }`}>
                      {selectedActors.has(a.id) ? "✓" : ""}
                    </span>
                    {a.country && <span className="text-sm">{COUNTRY_FLAGS[a.country] ?? ""}</span>}
                    <div className="min-w-0">
                      <div className="text-sm font-medium truncate">{a.name}</div>
                      <div className="text-[10px] text-[var(--text-secondary)] font-mono">{a.externalId}</div>
                    </div>
                  </div>
                  <span className="text-xs text-[var(--text-secondary)] shrink-0">{a.techniqueCount}</span>
                </button>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DownloadIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-[var(--text-secondary)]">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}
