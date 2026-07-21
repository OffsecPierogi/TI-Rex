"use client";

import { useRouter } from "next/navigation";
import { CATEGORY_LABELS, CATEGORY_COLORS, type StackComponent } from "@/lib/threat-model-data";

export function StackPicker({ components, selected }: { components: StackComponent[]; selected: string[] }) {
  const router = useRouter();

  function toggle(id: string) {
    const next = selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id];
    const params = new URLSearchParams();
    params.set("mode", "stack");
    if (next.length > 0) params.set("components", next.join(","));
    router.push(`/threat-model?${params.toString()}`);
  }

  const grouped = new Map<string, StackComponent[]>();
  for (const c of components) {
    const list = grouped.get(c.category) || [];
    list.push(c);
    grouped.set(c.category, list);
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--text-secondary)]">Select your technology stack</p>
        {selected.length > 0 && (
          <span className="badge bg-[var(--accent)] text-white">{selected.length} selected</span>
        )}
      </div>
      {Array.from(grouped.entries()).map(([cat, items]) => (
        <div key={cat}>
          <div className="flex items-center gap-2 mb-2">
            <span className={`badge ${CATEGORY_COLORS[cat] ?? "bg-zinc-800 text-zinc-400"}`}>
              {CATEGORY_LABELS[cat] ?? cat}
            </span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
            {items.map((c) => (
              <button key={c.id} onClick={() => toggle(c.id)}
                className={`p-3 rounded-lg text-sm text-left transition-all border ${
                  selected.includes(c.id)
                    ? "border-[var(--accent)] bg-[var(--accent)]/10 text-[var(--text-primary)]"
                    : "border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:border-[#3f3f46]"
                }`}>
                {c.name}
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
