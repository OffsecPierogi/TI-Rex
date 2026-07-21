"use client";

import { useRouter } from "next/navigation";
import type { IndustryProfile } from "@/lib/threat-model-data";

export function IndustryPicker({ profiles, selected }: { profiles: IndustryProfile[]; selected: string }) {
  const router = useRouter();

  function select(id: string) {
    const params = new URLSearchParams();
    params.set("mode", "industry");
    if (id !== selected) params.set("industry", id);
    router.push(`/threat-model?${params.toString()}`);
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
      {profiles.map((p) => (
        <button key={p.id} onClick={() => select(p.id)}
          className={`card text-left transition-all ${
            selected === p.id ? "border-[var(--accent)] shadow-[0_0_20px_rgba(59,130,246,0.1)]" : ""
          }`}>
          <div className="text-sm font-semibold">{p.name}</div>
          <div className="text-xs text-[var(--text-secondary)] mt-1">{p.description}</div>
          <div className="flex gap-1 flex-wrap mt-2">
            {p.primaryThreats.slice(0, 3).map((t) => (
              <span key={t} className="badge bg-zinc-800 text-zinc-400 text-[10px]">{t}</span>
            ))}
          </div>
        </button>
      ))}
    </div>
  );
}
